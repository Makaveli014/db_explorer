// тут лежит тестовый код
// менять вам может потребоваться только коннект к базе
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

var (
	// DSN это соединение с базой
	// вы можете изменить этот на тот который вам нужен
	// docker run -p 3306:3306 -v $(PWD):/docker-entrypoint-initdb.d -e MYSQL_ROOT_PASSWORD=1234 -e MYSQL_DATABASE=golang -d mysql
	// DSN = "root@tcp(localhost:3306)/golang2017?charset=utf8"
	//old_dsn
	//DSN = "coursera:5QPbAUufx7@tcp(localhost:3306)/coursera?charset=utf8"
	//new_dsn
	DSN = "root:1234@tcp(localhost:3307)/coursera?parseTime=true&charset=utf8mb4"
)

func main() {
	db, err := sql.Open("mysql", DSN)
	var dbname, host string
	var port, pid int
	_ = db.QueryRow("SELECT DATABASE()").Scan(&dbname)
	_ = db.QueryRow("SELECT @@hostname").Scan(&host)
	_ = db.QueryRow("SELECT @@port").Scan(&port)
	_ = db.QueryRow("SELECT CONNECTION_ID()").Scan(&pid)
	log.Printf("Connected: db=%s host=%s port=%d conn=%d", dbname, host, port, pid)

	if err != nil {
		panic(err)
	}

	err = db.Ping() // вот тут будет первое подключение к базе
	if err != nil {
		panic(err)
	}

	handler, err := NewDbExplorer(db)
	if err != nil {
		panic(err)
	}

	fmt.Println("starting server at :8082")
	http.ListenAndServe(":8082", handler)
}
