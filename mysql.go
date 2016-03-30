package utils

import (
    "database/sql"
    "fmt"
    _ "github.com/go-sql-driver/mysql"
    "reflect"
    "strings"
)

type Mysql struct {
    Db *sql.DB
}

func NewMysql(dsn string, maxConn int) (*Mysql, error) {
    db, err := sql.Open("mysql", dsn)

    if err != nil {
        return nil, err
    }

    db.SetMaxIdleConns(maxConn)
    db.SetMaxOpenConns(maxConn)

    return &Mysql{Db: db}, nil
}

func (this *Mysql) queryRows(sql string, rowsBool bool, v ...interface{}) (data []map[string]string) {
    rows, err := this.Db.Query(sql, v...)
    if err != nil {
        LogInfo.Write("execute query[%s][args:%v] error:%s", sql, v, err.Error())
        return
    }
    defer rows.Close()

    // 字段
    fields, err := rows.Columns()
    if err != nil {
        LogInfo.Write("execute query[%s][args:%v] get cols error:%s", sql, v, err.Error())
        return
    }

    var scanInterfaces []interface{}
    l := len(fields)
    for i := 0; i < l; i++ {
        var inter interface{}
        scanInterfaces = append(scanInterfaces, &inter)
    }

    i := 0
    for rows.Next() {
        i++
        err := rows.Scan(scanInterfaces...)
        if err != nil {
            LogInfo.Write("execute query[%s][args:%v] scan values error:%s", sql, v, err.Error())
            continue
        }

        row := make(map[string]string)
        for k, v := range fields {
            // 获取pointer真实的值
            value := reflect.Indirect(reflect.ValueOf(scanInterfaces[k]))

            if reflect.TypeOf(value.Interface()).Kind() == reflect.Slice {
                row[v] = fmt.Sprintf("%s", reflect.ValueOf(value.Interface()).Interface())
            } else {
                row[v] = fmt.Sprint(reflect.ValueOf(value.Interface()).Interface())
            }
        }

        data = append(data, row)
        if rowsBool != true && i > 0 {
            break
        }
    }

    return
}

func (this *Mysql) Query(sql string, v ...interface{}) (data []map[string]string) {
    return this.queryRows(sql, true, v...)
}

func (this *Mysql) QueryOne(sql string, v ...interface{}) (data map[string]string) {
    datas := this.queryRows(sql, false, v...)
    if len(datas) > 0 {
        data = datas[0]
    }

    return
}

func (this *Mysql) Exec(sql string, v ...interface{}) (int64, int64) {
    result, err := this.Db.Exec(sql, v...)

    if err != nil {
        LogInfo.Write("execute [%s][args:%v] error:%s", sql, v, err.Error())
        return -1, -1
    }

    rows, err := result.RowsAffected()
    if err != nil {
        LogInfo.Write("execute [%s][args:%v] get rows error:%s", sql, v, err.Error())
        return -1, -1
    }
    id, err := result.LastInsertId()
    if err != nil {
        LogInfo.Write("execute [%s][args:%v] get id error:%s", sql, v, err.Error())
        return rows, -1
    }

    return rows, id
}

func (this *Mysql) Count(sql string, v ...interface{}) int64 {
    data := this.QueryOne(sql, v...)
    for _, v := range data {
        return Atoi64(v)
    }

    return 0
}

func (this *Mysql) Update(table string, where map[string]interface{}, v map[string]interface{}) (b bool) {
    var whereStr string
    keys := Keys(where)
    var andStr string
    for _, k := range keys {
        whereStr += andStr + k + "=?"
        andStr = " AND "
    }
    var commaStr = ""
    keys = Keys(v)
    var updateStr string
    for _, k := range keys {
        updateStr += commaStr + k + "=?"
        commaStr = ", "
    }

    sql := fmt.Sprintf("UPDATE %s SET %s WHERE %s", table, updateStr, whereStr)
    var params []interface{}
    params = append(params, Values(v)...)
    params = append(params, Values(where)...)

    rows, _ := this.Exec(sql, params...)

    if rows >= 0 {
        b = true
    }

    return
}

func (this *Mysql) Insert(table string, v ...map[string]interface{}) (b bool, id int64) {
    if len(v) > 0 {
        first := v[0]
        keys := Keys(first)
        sql := "INSERT INTO " + table + "(" + strings.Join(keys, ", ") + ") VALUES"
        var params []interface{}
        var sqlValues []string
        for _, row := range v {
            var questionMarks []string
            for i := 0; i < len(row); i++ {
                questionMarks = append(questionMarks, "?")
            }
            sqlValues = append(sqlValues, strings.Join(questionMarks, ", "))
            params = append(params, Values(row)...)
        }
        var rows int64
        if len(v) == 1 {
            rows, id = this.Exec(sql + "(" + strings.Join(sqlValues, "), (") + ")", params...)
        } else {
            rows, _ = this.Exec(sql + "(" + strings.Join(sqlValues, "), (") + ")", params...)
        }

        if rows >= 0 {
            b = true
        }
    }

    return
}

func (this *Mysql) Replace(table string, v ...map[string]interface{}) (b bool) {
    if len(v) > 0 {
        first := v[0]
        keys := Keys(first)
        sql := "REPLACE INTO " + table + "(" + strings.Join(keys, ", ") + ") VALUES"
        var params []interface{}
        var sqlValues []string
        for _, row := range v {
            var questionMarks []string
            for i := 0; i < len(row); i++ {
                questionMarks = append(questionMarks, "?")
            }
            sqlValues = append(sqlValues, strings.Join(questionMarks, ", "))
            params = append(params, Values(row)...)
        }

        rows, _ := this.Exec(sql + "(" + strings.Join(sqlValues, "), (") + ")", params...)

        if rows >= 0 {
            b = true
        }
    }

    return
}
