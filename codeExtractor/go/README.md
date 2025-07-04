## Install Go

Install Go - [https://go.dev/doc/install](https://go.dev/doc/install)

## Build

```
go build codeExtractor.go
```

## Standalone usage

```
./codeExtractor <path> <method|struct name>
```

## Remark

In principle Go is correctly supported. However, compared to Java and C#, Claude responses were inconsistent which made the analysis fail, e.g.

Context code: `repository.BookRepository`

```
codeExtractor ./tests/go/go-webapp-sample-master repository.BookRepository
Error: definition BookRepository not found
```

Context code: `repository.NewBookRepository` (**same request** as above, just replayed)

```
codeExtractor ./tests/go/go-webapp-sample-master repository.NewBookRepository
{
  "filepath": "/home/ubuntu/repos/private/xvulnhuntr/tests/go/go-webapp-sample-master/repository/repository.go",
  "source": "func NewBookRepository(logger logger.Logger, conf *config.Config) Repository {\n\tlogger.GetZapLogger().Infof(\"Try database connection\")\n\tdb, err := connectDatabase(logger, conf)\n\tif err != nil {\n\t\tlogger.GetZapLogger().Errorf(\"Failure database connection\")\n\t\tos.Exit(config.ErrExitStatus)\n\t}\n\tlogger.GetZapLogger().Infof(\"Success database connection, %s:%s\", conf.Database.Host, conf.Database.Port)\n\treturn \u0026bookRepository{\u0026repository{db: db}}\n}",
  "type": "function"
}
```

To address the issue, xvulnhuntr implements an ugly hack: it issues a request to the LLM, it then tries to extract the context code returned, if codeExtractor fails then the exception is caught and another LLM request is attempted. It was observed that on the second or third request being replayed identically, the context code was correctly returned.