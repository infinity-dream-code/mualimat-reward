<?php

/**
 * Database class
 *
 * @author    Sven Wagener <wagener_at_indot_dot_de>
 * @copyright Sven Wagener
 * @include   Funktion:_include_
 */
class DbClass
{
    public string $database_types = "";

    public string $db_connect = "";
    public string $db_close = "";
    public string $db_select_db = "";
    public string $db_query = "";
    public string $db_fetch_array = "";
    public string $db_num_rows = "";
    public string $db_real_escape_string = "";

    public string $host;
    public string $database;
    public string $user;
    public string $password;
    public $port;
    public string $database_type;
    public $dsn;

    public $sql;
    public string $sqlstring = '';

    public $con; // variable for connection id
    public $con_string; // variable for connection string
    public $query_id; // variable for query id

    public $errors; // variable for error messages
    public int $error_count = 0; // variable for counting errors
    public $error_nr;
    public $error;

    public bool $debug = false; // debug mode off

    /**
     * Constructor of class - Initializes class and connects to the database
     * @param string $database_type the name of the database (ifx=Informix,msql=MiniSQL,mssql=MS SQL,mysql=MySQL,pg=Postgres SQL,sybase=Sybase)
     * @param string $host the host of the database
     * @param string $database the name of the database
     * @param string $user the name of the user for the database
     * @param string $password the passord of the user for the database
     * @param mixed $port The port number (optional)
     * @param mixed $dsn The DSN for ODBC connections (optional)
     * 
     * You can use these shortcuts for the database type:
     *   ifx -> INFORMIX
     *   msql -> MiniSQL
     *   mssql -> Microsoft SQL Server
     *   mysql -> MySQL
     *   odbc -> ODBC
     *   pg -> Postgres SQL
     *   sybase -> Sybase
     */
    public function __construct(string $database_type, string $host, string $database, string $user, string $password, $port = false, $dsn = false)
    {
        $database_type = strtolower($database_type);
        $this->host = $host;
        $this->database = $database;
        $this->user = $user;
        $this->password = $password;
        $this->port = $port;
        $this->dsn = $dsn;

        $this->database_types = ["ifx", "msql", "mssql", "mysql", "odbc", "pg", "sybase"];

        // Setting database type and connect to database
        if (in_array($database_type, $this->database_types)) {
            $this->database_type = $database_type;

            $this->db_connect = $this->database_type . "_connect";
            $this->db_close = $this->database_type . "_close";
            $this->db_select_db = $this->database_type . "_select_db";

            if ($database_type == "odbc") {
                $this->db_query = $this->database_type . "_exec";
                $this->db_fetch_array = $this->database_type . "_fetch_row";
            } else {
                $this->db_query = $this->database_type . "_query";
                $this->db_fetch_array = $this->database_type . "_fetch_array";
            }

            $this->db_num_rows = $this->database_type . "_num_rows";
            $this->db_real_escape_string = $this->database_type . "_real_escape_string";

            $this->connect();
        } else {
            $this->halt("Database type not supported");
        }
    }

    // Legacy constructor for backward compatibility
    public function database(string $database_type, string $host, string $database, string $user, string $password, $port = false, $dsn = false)
    {
        self::__construct($database_type, $host, $database, $user, $password, $port, $dsn);
    }

    /**
     * This function connects the database
     * @return bool Returns true if connection was successful otherwise false
     */
    public function connect(): bool
    {
        if ($this->con == "") {
            // INFORMIX
            if ($this->database_type == "ifx") {
                $this->con = call_user_func($this->db_connect, $this->database . "@" . $this->host, $this->user, $this->password);
            } elseif ($this->database_type == "mysql") {
                // With port
                if ($this->port) {
                    $this->con = call_user_func($this->db_connect, $this->host . ":" . $this->port, $this->user, $this->password);
                } else {
                    // Without port
                    $this->con = call_user_func($this->db_connect, $this->host, $this->user, $this->password);
                }
            } elseif ($this->database_type == "msql") {
                // mSQL
                $this->con = call_user_func($this->db_connect, $this->host, $this->user, $this->password);
            } elseif ($this->database_type == "mssql") {
                // MS SQL Server
                $this->con = call_user_func($this->db_connect, $this->host, $this->user, $this->password);
            } elseif ($this->database_type == "odbc") {
                // ODBC
                $this->con = call_user_func($this->db_connect, $this->dsn, $this->user, $this->password);
            } elseif ($this->database_type == "pg") {
                // Postgres SQL
                if ($this->port) {
                    $this->con = call_user_func($this->db_connect, "host=" . $this->host . " port=" . $this->port . " dbname=" . $this->database . " user=" . $this->user . " password=" . $this->password);
                } else {
                    // Without port
                    $this->con = call_user_func($this->db_connect, "host=" . $this->host . " dbname=" . $this->database . " user=" . $this->user . " password=" . $this->password);
                }
            } elseif ($this->database_type == "sybase") {
                // Sybase
                $this->con = call_user_func($this->db_connect, $this->host, $this->user, $this->password);
            }

            if (!$this->con) {
                $this->halt("Wrong connection data! Can't establish connection to host.");
                return false;
            } else {
                if ($this->database_type != "odbc") {
                    if (!call_user_func($this->db_select_db, $this->database, $this->con)) {
                        $this->halt("Wrong database data! Can't select database.");
                        return false;
                    }
                }
                return true;
            }
        } else {
            $this->halt("Already connected to database.");
            return false;
        }
    }

    /**
     * This function disconnects from the database
     * @return bool Returns true if disconnected successfully, false otherwise
     */
    public function disconnect(): bool
    {
        if (@call_user_func($this->db_close, $this->con)) {
            return true;
        } else {
            $this->halt("Not connected yet");
            return false;
        }
    }

    public function __destruct()
    {
        $this->disconnect();
    }

    /**
     * This function starts the sql query
     * @param string $sql_statement the sql statement
     * @return bool Returns false on errors otherwise true
     */
    public function query(string $sql_statement): bool
    {
        $this->sql = $sql_statement;
        if ($this->debug) {
            printf("SQL statement: %s\n", $this->sql);
        }
        
        if ($this->database_type == "odbc") {
            // ODBC
            $this->query_id = call_user_func($this->db_query, $this->con, $this->sql);
        } else {
            // All other databases
            $this->query_id = call_user_func($this->db_query, $this->con, $this->sql);
        }

        if (!$this->query_id) {
            $this->halt("Invalid SQL Query: " . $this->sql);
            return false;
        }
        return true;
    }

    /**
     * This function returns a row of the resultset
     * @return array|false The row as array or false if there is no more row
     */
    public function get_row()
    {
        if ($this->database_type == "odbc") {
            // ODBC database
            if ($row = call_user_func($this->db_fetch_array, $this->query_id)) {
                $row_array = [];
                for ($i = 1; $i <= odbc_num_fields($this->query_id); $i++) {
                    $fieldname = odbc_field_name($this->query_id, $i);
                    $row_array[$fieldname] = odbc_result($this->query_id, $i);
                }
                return $row_array;
            }
            return false;
        } else {
            // All other databases
            return call_user_func($this->db_fetch_array, $this->query_id);
        }
    }

    /**
     * This function returns number of rows in the resultset
     * @return int|false The number of rows in the resultset or false on error
     */
    public function count_rows()
    {
        $row_count = call_user_func($this->db_num_rows, $this->query_id);
        if ($row_count >= 0) {
            return $row_count;
        } else {
            $this->halt("Can't count rows before query was made");
            return false;
        }
    }

    /**
     * This function returns all tables of the database in an array
     * @return array All tables of the database
     */
    public function get_tables(): array
    {
        if ($this->database_type == "odbc") {
            // ODBC databases
            $tablelist = odbc_tables($this->con);
            $tables = [];
            for ($i = 0; odbc_fetch_row($tablelist); $i++) {
                $tables[$i] = odbc_result($tablelist, 3);
            }
            return $tables;
        } else {
            // All other databases
            $tables = [];
            $sql = "SHOW TABLES";
            $this->query($sql);
            for ($i = 0; $data = $this->get_row(); $i++) {
                $tables[$i] = $data['Tables_in_' . $this->database];
            }
            return $tables;
        }
    }

    /**
     * Prints out a error message
     * @param string $message The error message
     */
    public function halt(string $message): void
    {
        if ($this->debug) {
            printf("Database error: %s\n", $message);
            if ($this->error_nr != "" && $this->error != "") {
                printf("MySQL Error: %s (%s)\n", $this->error_nr, $this->error);
            }
            die("Session halted.");
        }
    }

    /**
     * Switches to debug mode
     * @param bool $debug Whether to enable debug mode
     */
    public function debug_mode(bool $debug = true): void
    {
        $this->debug = $debug;
    }

    /**
     * Escapes a string for safe use in SQL queries
     * @param string $s_string The string to escape
     * @return string|false The escaped string or false on failure
     */
    public function real_escape_string(string $s_string)
    {
        $this->sqlstring = $s_string;
        $new_string = call_user_func($this->db_real_escape_string, $this->con, $this->sqlstring);
        
        if ($new_string) {
            return $new_string;
        } else {
            $this->halt("Can't execute " . $this->db_real_escape_string);
            return false;
        }
    }
}
