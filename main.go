// Note: Compare between section 5.1 files. Session and filtering not working correctly

package main

import (
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	gmux "github.com/gorilla/mux"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	negroni2 "github.com/urfave/negroni"
	"github.com/yosssi/ace"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gorp.v1"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

type Book struct {
	PK             int64  `db:"pk"`
	Title          string `db:"title"`
	Author         string `db:"author"`
	Classification string `db:"classification"`
	ID             string `db:"id"`
	User           string `db:"user"`
}

type User struct {
	Username string `db:"username"`
	Secret   []byte `db:"secret"`
}

type Page struct {
	Books  []Book
	Filter string
	User   string
}

type SearchResult struct {
	Title  string `xml:"title,attr"`
	Author string `xml:"author,attr"`
	Year   string `xml:"hyr,attr"`
	ID     string `xml:"owi,attr"`
}

var db *sql.DB
var dbmap *gorp.DbMap

func initDb() {
	if os.Getenv("ENV") != "production" {
		db, _ = sql.Open("sqlite3", "dev.db")
		dbmap = &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
	} else {
		db, _ = sql.Open("postgres", os.Getenv("DATABASE_URL"))
		dbmap = &gorp.DbMap{Db: db, Dialect: gorp.PostgresDialect{}}
	}

	dbmap.AddTableWithName(Book{}, "books").SetKeys(true, "pk")
	dbmap.AddTableWithName(User{}, "users").SetKeys(false, "username")
	if err := dbmap.CreateTablesIfNotExists(); err != nil {
		panic(err)
	}
}

func verifyDatabase(writer http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
	if err := db.Ping(); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	next(writer, request)
}

func getBookCollection(books *[]Book, sortCol, filterByClass, username string, writer http.ResponseWriter) bool {
	if sortCol == "" {
		sortCol = "pk"
	}
	where := " where \"user\"=" + dbmap.Dialect.BindVar(0)
	if filterByClass == "fiction" {
		where += " and classification between '800' and '900'"
	} else if filterByClass == "nonfiction" {
		where += " and classification not between '800' and '900'"
	}
	if _, err := dbmap.Select(books, "select * from books"+where+" order by "+sortCol, username); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return false
	}
	return true
}

func getStringFromSession(request *http.Request, key string) string {
	var strVal string
	if val := sessions.GetSession(request).Get(key); val != nil {
		strVal = val.(string)
	}
	return strVal
}

func verifyUser(writer http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
	if request.URL.Path == "/login" {
		next(writer, request)
		return
	}
	if username := getStringFromSession(request, "User"); username != "" {
		if user, _ := dbmap.Get(User{}, username); user != nil {
			next(writer, request)
			return
		}
	}
	http.Redirect(writer, request, "/login", http.StatusTemporaryRedirect)
}

type LoginPage struct {
	Error string
}

func main() {
	initDb()

	mux := gmux.NewRouter()

	mux.HandleFunc("/login", func(writer http.ResponseWriter, request *http.Request) {
		var p LoginPage
		if request.FormValue("register") != "" {
			secret, _ := bcrypt.GenerateFromPassword([]byte(request.FormValue("password")), bcrypt.DefaultCost)
			user := User{request.FormValue("username"), secret}
			if err := dbmap.Insert(&user); err != nil {
				p.Error = err.Error()
			} else {
				sessions.GetSession(request).Set("User", user.Username)
				http.Redirect(writer, request, "/", http.StatusFound)
				return
			}
		} else if request.FormValue("login") != "" {
			user, err := dbmap.Get(User{}, request.FormValue("username"))
			if err != nil {
				p.Error = err.Error()
			} else if user == nil {
				p.Error = "No such user found with Username: " + request.FormValue("username")
			} else {
				u := user.(*User)
				if err = bcrypt.CompareHashAndPassword(u.Secret, []byte(request.FormValue("password"))); err != nil {
					p.Error = err.Error()
				} else {
					sessions.GetSession(request).Set("User", u.Username)
					http.Redirect(writer, request, "/", http.StatusFound)
					return
				}
			}
		}

		template, err := ace.Load("templates/login", "", nil)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		if err = template.Execute(writer, p); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/logout", func(writer http.ResponseWriter, request *http.Request) {
		sessions.GetSession(request).Set("User", nil)
		sessions.GetSession(request).Set("Filter", nil)

		http.Redirect(writer, request, "/login", http.StatusFound)
	})

	mux.HandleFunc("/books", func(writer http.ResponseWriter, request *http.Request) {
		var b []Book
		if !getBookCollection(&b, getStringFromSession(request, "SortBy"), request.FormValue("filter"),
			getStringFromSession(request, "User"), writer) {
			return
		}

		sessions.GetSession(request).Set("filter", request.FormValue("filter"))

		if err := json.NewEncoder(writer).Encode(b); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}).Methods("GET").Queries("filter", "{filter:all|fiction|nonfiction}")

	mux.HandleFunc("/books", func(writer http.ResponseWriter, request *http.Request) {
		var b []Book
		if !getBookCollection(&b, request.FormValue("sortBy"), getStringFromSession(request, "Filter"),
			getStringFromSession(request, "User"), writer) {
			return
		}

		sessions.GetSession(request).Set("SortBy", request.FormValue("sortBy"))

		if err := json.NewEncoder(writer).Encode(b); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}).Methods("GET").Queries("sortBy", "{sortBy:title|author|classification}")

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		template, err := ace.Load("templates/index", "", nil)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		p := Page{Books: []Book{}, Filter: getStringFromSession(request, "Filter"), User: getStringFromSession(request, "User")}
		if !getBookCollection(&p.Books, getStringFromSession(request, "SortBy"),
			getStringFromSession(request, "Filter"), p.User, writer) {
			return
		}

		if err = template.Execute(writer, p); err != nil { //err := templates.ExecuteTemplate(writer, "index.html", p); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		}
	}).Methods("GET")

	mux.HandleFunc("/search", func(writer http.ResponseWriter, request *http.Request) {
		var results []SearchResult
		var err error

		if results, err = search(request.FormValue("search")); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		encoder := json.NewEncoder(writer)
		if err := encoder.Encode(results); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		}
	}).Methods("POST")

	mux.HandleFunc("/books", func(writer http.ResponseWriter, request *http.Request) {
		var book ClassifyBookResponse
		var err error

		if book, err = find(request.FormValue("id")); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		b := Book{
			PK:             -1,
			Title:          book.BookData.Title,
			Author:         book.BookData.Author,
			Classification: book.Classification.MostPopular,
			ID:             request.FormValue("id"),
			User:           getStringFromSession(request, "User"),
		}
		if err = dbmap.Insert(&b); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := json.NewEncoder(writer).Encode(b); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		}
	}).Methods("PUT")

	mux.HandleFunc("/books/{pk}", func(writer http.ResponseWriter, request *http.Request) {
		pk, _ := strconv.ParseInt(gmux.Vars(request)["pk"], 10, 64)
		var b Book
		q := "select * from books where pk=" + dbmap.Dialect.BindVar(0) + " and \"user\"=" + dbmap.Dialect.BindVar(1)
		if err := dbmap.SelectOne(&b, q, pk, getStringFromSession(request, "User")); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
		}
		if _, err := dbmap.Delete(&b); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}).Methods("DELETE")

	negroni := negroni2.Classic()
	negroni.Use(sessions.Sessions("go-for-web-dev", cookiestore.New([]byte("my-secret-123"))))
	negroni.Use(negroni2.HandlerFunc(verifyDatabase))
	negroni.Use(negroni2.HandlerFunc(verifyUser))
	negroni.UseHandler(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	negroni.Run(":" + port)
}

//	fmt.Println(http.ListenAndServe("localhost:8080", nil))

type ClassifySearchResponse struct {
	Results []SearchResult `xml:"works>work"`
}

type ClassifyBookResponse struct {
	BookData struct {
		Title  string `xml:"title,attr"`
		Author string `xml:"author,attr"`
		ID     string `xml:"owi,attr"`
	} `xml:"work"`
	Classification struct {
		MostPopular string `xml:"sfa,attr"`
	} `xml:"recommendations>ddc>mostPopular"`
}

func find(id string) (ClassifyBookResponse, error) {
	var c ClassifyBookResponse
	body, err := classifyAPI("http://classify.oclc.org/classify2/Classify?summary=true&owi=" + url.QueryEscape(id))
	if err != nil {
		return ClassifyBookResponse{}, err
	}

	err = xml.Unmarshal(body, &c)
	return c, err
}

func search(query string) ([]SearchResult, error) {
	var c ClassifySearchResponse
	body, err := classifyAPI("http://classify.oclc.org/classify2/Classify?summary=true&title=" + url.QueryEscape(query))
	if err != nil {
		return []SearchResult{}, err
	}
	err = xml.Unmarshal(body, &c)
	return c.Results, err
}

func classifyAPI(url string) ([]byte, error) {
	var resp *http.Response
	var err error

	if resp, err = http.Get(url); err != nil {
		return []byte{}, err
	}

	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}
