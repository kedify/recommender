package main

import (
	"flag"
	"fmt"
	"strings"
)

var (
	pghost     = "127.0.0.1"
	pguser     = "postgres"
	pgdbname   = "postgres"
	pgpassword = ""
	pgport     = 5432
	pgsslmode  = "disable"

	kedifyServerAddr = "104.197.243.58:443"
)

func main() {
	flag.StringVar(&pghost, "pghost", pghost, "Postgres host")
	flag.StringVar(&pguser, "pguser", pguser, "Postgres user")
	flag.StringVar(&pgdbname, "pgdbname", pgdbname, "Postgres dbname")
	flag.StringVar(&pgpassword, "pgpassword", pgpassword, "Postgres password")
	flag.IntVar(&pgport, "pgport", pgport, "Postgres port")
	flag.StringVar(&pgsslmode, "pgsslmode", pgsslmode, "Postgres sslmode")
	flag.StringVar(&kedifyServerAddr, "kedify-server-addr", kedifyServerAddr, "Kedify server address")
	flag.Parse()
	postgresArgs := []string{fmt.Sprintf("host=%s", pghost)}
	postgresArgs = append(postgresArgs, fmt.Sprintf("user=%s", pguser))
	postgresArgs = append(postgresArgs, fmt.Sprintf("dbname=%s", pgdbname))
	if pgpassword != "" {
		postgresArgs = append(postgresArgs, fmt.Sprintf("password=%s", pgpassword))
	}
	postgresArgs = append(postgresArgs, fmt.Sprintf("port=%d", pgport))
	if pgsslmode != "" {
		postgresArgs = append(postgresArgs, fmt.Sprintf("sslmode=%s", pgsslmode))
	}
	postgresDSN := strings.Join(postgresArgs, " ")
}
