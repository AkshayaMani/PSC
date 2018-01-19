package logging

import (
    "io"
    "log"
    "os"
)

var (
    Info    *log.Logger
    Warning *log.Logger
    Error   *log.Logger
)

func Init(
    infoHandle io.Writer,
    warningHandle io.Writer,
    errorHandle io.Writer) {

    Info = log.New(infoHandle,
        "[INFO] ",
        log.Ldate|log.Ltime|log.Lshortfile)

    Warning = log.New(warningHandle,
        "[WARNING] ",
        log.Ldate|log.Ltime|log.Lshortfile)

    Error = log.New(errorHandle,
        "[ERROR] ",
        log.Ldate|log.Ltime|log.Lshortfile)
}

func LogToFile(filename string) {

    file, _ := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    Init(io.MultiWriter(file, os.Stdout), io.MultiWriter(file, os.Stdout), io.MultiWriter(file, os.Stderr))
}

/*func main() {
    file, _ := os.OpenFile("CPlog", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    Init(io.MultiWriter(file, os.Stdout), io.MultiWriter(file, os.Stdout), io.MultiWriter(file, os.Stderr))

    Info.Println("Special Information")
    Warning.Println("There is something you need to know about")
    Error.Println("Something has failed")
}*/
