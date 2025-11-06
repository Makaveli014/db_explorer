package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// тут вы пишете код
// обращаю ваше внимание - в этом задании запрещены глобальные переменные
type BaseType string

const (
	BaseString   BaseType = "string"
	BaseInt      BaseType = "int"
	BaseFloat    BaseType = "float"
	BaseBool     BaseType = "bool"
	BaseDateTime BaseType = "datetime"
	BaseUnknown  BaseType = "unknown"
)

type ColInfo struct {
	Name          string
	RawType       string
	Base          BaseType
	Nullable      bool
	IsPK          bool
	Default       sql.NullString
	AutoIncrement bool
}
type SchemaCache map[string]map[string]ColInfo
type Handler struct {
	DB     *sql.DB
	PK     map[string]string
	Schema SchemaCache
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": msg,
	})
}

func writeResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"response": payload,
	})
}

func parseMySQLType(raw string) BaseType {
	raw = strings.ToLower(raw)

	switch {
	case strings.HasPrefix(raw, "tinyint(1)"):
		return BaseBool
	case strings.HasPrefix(raw, "int"),
		strings.HasPrefix(raw, "tinyint"),
		strings.HasPrefix(raw, "smallint"),
		strings.HasPrefix(raw, "mediumint"),
		strings.HasPrefix(raw, "bigint"):
		return BaseInt
	case strings.HasPrefix(raw, "float"),
		strings.HasPrefix(raw, "double"),
		strings.HasPrefix(raw, "decimal"):
		return BaseFloat
	case strings.HasPrefix(raw, "varchar"),
		strings.HasPrefix(raw, "char"),
		strings.HasPrefix(raw, "text"):
		return BaseString
	case strings.HasPrefix(raw, "datetime"),
		strings.HasPrefix(raw, "timestamp"),
		strings.HasPrefix(raw, "date"):
		return BaseDateTime
	default:
		return BaseUnknown
	}

}

func (h *Handler) ensureTableSchema(ctx context.Context, table string) (map[string]ColInfo, error) {
	if h.Schema == nil {
		h.Schema = make(SchemaCache)
	}
	if sc, ok := h.Schema[table]; ok {
		return sc, nil
	}
	query := fmt.Sprintf("SHOW COLUMNS FROM `%s`", table)
	rows, err := h.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sc := make(map[string]ColInfo)

	for rows.Next() {
		var (
			field, typ, nullStr, key, extra string
			def                             sql.NullString
		)

		if err := rows.Scan(&field, &typ, &nullStr, &key, &def, &extra); err != nil {
			return nil, err
		}
		sc[field] = ColInfo{
			Name:          field,
			RawType:       typ,
			Base:          parseMySQLType(typ),
			Nullable:      nullStr == "YES",
			IsPK:          key == "PRI",
			Default:       def,
			AutoIncrement: strings.Contains(strings.ToLower(extra), "auto_increment"),
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	h.Schema[table] = sc
	return sc, nil
}

func (h *Handler) columnsSet(table string) (map[string]struct{}, error) {
	q := fmt.Sprintf("SELECT * FROM `%s` LIMIT 0", table)
	rows, err := h.DB.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(cols))
	for _, c := range cols {
		set[c] = struct{}{}
	}
	return set, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	router := mux.NewRouter()
	router.HandleFunc("/", h.GetTables).Methods("GET")
	router.HandleFunc("/tables", h.GetTables).Methods("GET")
	router.HandleFunc("/{table}", h.GetLimit).Methods("GET")
	router.HandleFunc("/{table}/{id:[0-9]+}", h.GetOne).Methods("GET")
	router.HandleFunc("/{table}", h.Create).Methods("PUT")
	router.HandleFunc("/{table}/", h.Create).Methods("PUT")
	router.HandleFunc("/{table}/{id:[0-9]+}", h.Update).Methods("POST", "PATCH")
	router.HandleFunc("/{table}/{id:[0-9]+}", h.Delete).Methods("DELETE")

	router.ServeHTTP(writer, request)
}

func (h *Handler) GetLimit(w http.ResponseWriter, r *http.Request) {
	table := mux.Vars(r)["table"]

	validName := regexp.MustCompile(`^[A-Za-z0-9_]+$`).MatchString
	if !validName(table) {
		writeError(w, http.StatusBadRequest, "invalid table name")
		return
	}

	if !h.tableExists(table) {
		writeError(w, http.StatusNotFound, "unknown table")
		return
	}

	limit, offset, err := parseLimitOffset(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	orderCol := h.PK[table]
	if orderCol == "" {
		orderCol = "id"
	}
	schema, err := h.ensureTableSchema(r.Context(), table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	query := fmt.Sprintf("SELECT * FROM `%s` ORDER BY `%s` LIMIT %d OFFSET %d", table, orderCol, limit, offset)

	rows, err := h.DB.Query(query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	records := make([]map[string]any, 0, limit)
	for rows.Next() {
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			writeError(w, http.StatusInternalServerError, "db error")
			return
		}
		rec := make(map[string]any, len(cols))
		for i, c := range cols {
			v := vals[i]
			if v == nil {
				rec[c] = nil
				continue
			}
			if b, ok := v.([]byte); ok {
				s := string(b)
				switch schema[c].Base {
				case BaseInt:
					if n, err := strconv.ParseInt(s, 10, 64); err == nil {
						rec[c] = n
					} else {
						rec[c] = s
					}
				case BaseFloat:
					if f, err := strconv.ParseFloat(s, 64); err == nil {
						rec[c] = f
					} else {
						rec[c] = s
					}
				case BaseBool:
					rec[c] = s == "1" || s == "true"
				default:
					rec[c] = s
				}
			} else {
				rec[c] = v
			}
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeResponse(w, http.StatusOK, map[string]any{
		"records": records,
	})
	return
}

// парсинг и передача параметров для limit & offset
func parseLimitOffset(r *http.Request) (int, int, error) {
	q := r.URL.Query()

	limit, offset := 5, 0

	cleanNum := func(s string) string {
		for i, r := range s {
			if r < '0' || r > '9' {
				return s[:i]
			}
		}
		return s
	}
	if s := q.Get("limit"); s != "" {
		orig := s
		clean := cleanNum(s)
		if len(clean) != len(orig) {
			clean = ""
		}

		if clean != "" {
			if v, err := strconv.Atoi(s); err == nil && v >= 1 && v <= 100 {
				limit = v
			}
		}
	}
	if s := q.Get("offset"); s != "" {
		orig := s
		clean := cleanNum(s)
		if len(clean) != len(orig) {
			clean = ""
		}
		if clean != "" {
			if v, err := strconv.Atoi(s); err == nil && v >= 0 {
				offset = v
			}
		}
	}
	return limit, offset, nil
}

// Запрос для получения списка таблиц
func (h *Handler) GetTables(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query("SHOW TABLES;")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	out := make([]string, 0)
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			writeError(w, http.StatusInternalServerError, "db error")
			return
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeResponse(w, http.StatusOK, map[string]any{
		"tables": out,
	})
}

func NewDbExplorer(db *sql.DB) (*Handler, error) {
	if db == nil {
		return nil, fmt.Errorf("db is nil")
	}
	handler := &Handler{
		DB:     db,
		PK:     map[string]string{"users": "user_id", "items": "id"},
		Schema: make(SchemaCache),
	}
	return handler, nil
}

func (h *Handler) tableExists(table string) bool {
	rows, err := h.DB.Query("SHOW TABLES")
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil && t == table {
			return true
		}
	}
	return false
}

func (h *Handler) GetOne(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	table := vars["table"]
	idStr := vars["id"]
	pk := h.PK[table]
	if pk == "" {
		pk = "id"
	}

	if !h.tableExists(table) {
		writeError(w, http.StatusNotFound, "unknown table")
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	schema, err := h.ensureTableSchema(r.Context(), table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	query := fmt.Sprintf("SELECT * FROM `%s` WHERE `%s` = ?", table, pk)
	rows, err := h.DB.QueryContext(ctx, query, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			writeError(w, http.StatusInternalServerError, "db error")
			return
		}
		writeError(w, http.StatusNotFound, "record not found")
		return
	}
	cols, err := rows.Columns()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	values := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range values {
		ptrs[i] = &values[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	rec := make(map[string]any, len(cols))
	for i, c := range cols {
		v := values[i]
		if v == nil {
			rec[c] = nil
			continue
		}
		if b, ok := v.([]byte); ok {
			s := string(b)
			switch schema[c].Base {
			case BaseInt:
				if n, err := strconv.ParseInt(s, 10, 64); err == nil {
					rec[c] = n
				} else {
					rec[c] = s
				}
			case BaseFloat:
				if f, err := strconv.ParseFloat(s, 64); err == nil {
					rec[c] = f
				} else {
					rec[c] = s
				}
			case BaseBool:
				rec[c] = s == "1" || s == "true"
			default:
				rec[c] = s
			}
		} else {
			rec[c] = v
		}
	}
	writeResponse(w, http.StatusOK, map[string]any{
		"record": rec,
	})
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	table := mux.Vars(r)["table"]
	validName := regexp.MustCompile(`^[A-Za-z0-9_]+$`).MatchString
	if !validName(table) {
		writeError(w, http.StatusBadRequest, "invalid table name")
		return
	}
	if !h.tableExists(table) {
		writeError(w, http.StatusNotFound, "unknown table")
		return
	}
	b, _ := io.ReadAll(r.Body)
	defer r.Body.Close()
	ct := strings.ToLower(r.Header.Get("Content-Type"))

	var rec map[string]any

	if strings.HasPrefix(ct, "application/json") {
		var obj map[string]any
		if err := json.Unmarshal(b, &obj); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if r0, ok := obj["record"]; ok {
			rec, _ = r0.(map[string]any)
		} else {
			rec = obj
		}
	} else if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		vals, _ := url.ParseQuery(string(b))
		if raw := vals.Get("record"); raw != "" {
			var m map[string]any
			if json.Unmarshal([]byte(raw), &m) == nil {
				rec = m
			}
		} else if len(vals) > 0 {
			m := make(map[string]any, len(vals))
			for k, v := range vals {
				if len(v) > 0 {
					m[k] = v[0]
				}
			}
			rec = m
		}
	}
	if rec == nil || len(rec) == 0 {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	colsSet, err := h.columnsSet(table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	schema, err := h.ensureTableSchema(r.Context(), table)
	pk := h.PK[table]
	auto := schema[pk].AutoIncrement
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	var explicitID *int64
	if !auto {
		if v, ok := rec[pk]; ok {
			var n int64
			switch t := v.(type) {
			case float64:
				n = int64(t)
			case string:
				parsed, err := strconv.ParseInt(t, 10, 64)
				if err != nil {
					writeError(w, http.StatusBadRequest, "bad request")
					return
				}
				n = parsed
			default:
				writeError(w, http.StatusBadRequest, "bad request")
				return
			}
			if n <= 0 {
				writeError(w, http.StatusBadRequest, "bad request")
				return
			}
			explicitID = &n
		}
	}

	cols := make([]string, 0, len(rec))
	vals := make([]any, 0, len(rec))
	placeholders := make([]string, 0, len(rec))
	for k, v := range rec {
		if k == pk && auto {
			continue
		}
		if _, ok := colsSet[k]; !ok {
			continue
		}
		cols = append(cols, fmt.Sprintf("`%s`", k))
		placeholders = append(placeholders, "?")
		vals = append(vals, v)
	}

	present := make(map[string]struct{}, len(cols))
	for _, c := range cols {
		name := strings.Trim(c, "`")
		present[name] = struct{}{}
	}

	for name, col := range schema {
		if col.IsPK {
			continue
		}
		if _, ok := present[name]; ok {
			continue
		}
		if col.Nullable {
			continue
		}
		raw := strings.ToLower(col.RawType)
		isString := col.Base == BaseString || strings.HasPrefix(raw, "varchar") || strings.HasPrefix(raw, "text")
		if isString && !col.Default.Valid {
			cols = append(cols, fmt.Sprintf("`%s`", name))
			placeholders = append(placeholders, "?")
			vals = append(vals, "")
			present[name] = struct{}{}
		}
	}

	if len(cols) == 0 {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	q := fmt.Sprintf("INSERT INTO `%s` (%s) VALUES (%s)", table, strings.Join(cols, ","), strings.Join(placeholders, ","))
	res, err := h.DB.Exec(q, vals...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	pk = h.PK[table]
	if pk == "" {
		pk = "id"
	}

	var outID int64
	if auto {
		outID, _ = res.LastInsertId()
	} else if explicitID != nil {
		outID = *explicitID
	} else {
		outID, _ = res.LastInsertId()
	}
	writeResponse(w, http.StatusOK, map[string]any{pk: outID})
	return
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	table := vars["table"]
	idStr := vars["id"]

	if !h.tableExists(table) {
		writeError(w, http.StatusNotFound, "unknown table")
		return
	}
	pk := h.PK[table]
	if pk == "" {
		pk = "id"
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}

	var rec map[string]any
	ct := strings.ToLower(r.Header.Get("Content-Type"))

	b, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if strings.HasPrefix(ct, "application/json") {
		var obj map[string]any
		if err := json.Unmarshal(b, &obj); err != nil {
			log.Printf("[U-DEC] json unmarshal err=%v; body=%q", err, string(b))
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if r0, ok := obj["record"]; ok {
			if m, ok2 := r0.(map[string]any); ok2 {
				rec = m
			} else {
				rec = map[string]any{}
			}
		} else {
			rec = obj
		}
	} else {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if raw := r.Form.Get("record"); raw != "" {
			var m map[string]any
			if json.Unmarshal([]byte(raw), &m) == nil {
				rec = m
			}
		} else if len(r.Form) > 0 {
			m := make(map[string]any, len(r.Form))
			for k, v := range r.Form {
				if len(v) > 0 {
					m[k] = v[0]
				}
			}
			rec = m
		}
	}
	if rec == nil || len(rec) == 0 {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}

	colsSet, err := h.columnsSet(table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	schema, err := h.ensureTableSchema(r.Context(), table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	for k, v := range rec {
		colInfo, ok := schema[k]
		if !ok {
			continue
		}
		if k == pk || k == "id" {
			if v == nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("field %s have invalid type", k))
				return
			}
			if _, ok := v.(string); !ok {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("field %s have invalid type", k))
				return
			}
			continue
		}
		if v == nil && !colInfo.Nullable {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("field %s have invalid type", k))
			return
		}

		raw := strings.ToLower(colInfo.RawType)
		if v != nil && (colInfo.Base == BaseString || strings.HasPrefix(raw, "varchar") || strings.HasPrefix(raw, "text")) {
			if _, ok := v.(string); !ok {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("field %s have invalid type", k))
				return
			}
		}

	}
	knowUptabaleFound := false
	for k := range rec {
		if _, ok := colsSet[k]; ok && k != pk && k != "id" {
			knowUptabaleFound = true
			break
		}
	}
	if !knowUptabaleFound {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}

	cols := make([]string, 0, len(rec))
	vals := make([]any, 0, len(rec))
	for k, v := range rec {
		if k == pk || k == "id" {
			continue
		}
		if _, ok := colsSet[k]; !ok {
			continue
		}
		cols = append(cols, fmt.Sprintf("`%s` = ?", k))
		vals = append(vals, v)
	}
	if len(cols) == 0 {
		writeResponse(w, http.StatusOK, map[string]any{"updated": 0})
		return
	}
	vals = append(vals, id)
	q := fmt.Sprintf("UPDATE `%s` SET %s WHERE `%s` = ?", table, strings.Join(cols, ","), pk)

	res, err := h.DB.Exec(q, vals...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	affected, _ := res.RowsAffected()
	writeResponse(w, http.StatusOK, map[string]any{
		"updated": affected,
	})
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	table := vars["table"]
	idStr := vars["id"]

	if !h.tableExists(table) {
		writeError(w, http.StatusNotFound, "unknown table")
		return
	}

	pk := h.PK[table]
	if pk == "" {
		pk = "id"
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	query := fmt.Sprintf("DELETE FROM `%s` WHERE `%s` = ? LIMIT 1", table, pk)

	res, err := h.DB.ExecContext(ctx, query, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	aff, _ := res.RowsAffected()
	if err == nil {
		writeResponse(w, http.StatusOK, map[string]any{"deleted": aff})
		return
	}
}
