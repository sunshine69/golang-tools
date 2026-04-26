# Package [github.com/sunshine69/golang-tools/utils](https://pkg.go.dev/github.com/sunshine69/golang-tools/utils?tab=doc)

```go
import github.com/sunshine69/golang-tools/utils
```


## Constants
### TimeISO8601LayOut, AUTimeLayout, CleanStringDateLayout, LetterCharset, PasswordCharset
```go
TimeISO8601LayOut = "2006-01-02T15:04:05-0700"
AUTimeLayout = "02/01/2006 15:04:05 MST"
CleanStringDateLayout = "2006-01-02-150405"
LetterCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^()-,."
// remove \ as not json friendly, json seems to be fine. No quotes to make yaml happy
PasswordCharset = `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`

```
TimeISO8601LayOut

### MillisPerSecond, NanosPerMillisecond, NanosPerSecond
```go
MillisPerSecond = int64(time.Second / time.Millisecond)
NanosPerMillisecond = int64(time.Millisecond / time.Nanosecond)
NanosPerSecond = int64(time.Second / time.Nanosecond)

```
Time handling

### EncryptVersion1, EncryptVersion2
```go
EncryptVersion1 = byte(1) // argon2id, only recent go version supports it, this is default

EncryptVersion2 = byte(2) // scrypt version, good enough


```



## Variables
### ErrMacMismatch, ErrBadHeader
```go
ErrMacMismatch = fmt.Errorf("authentication failed: HMAC mismatch")
ErrBadHeader = fmt.Errorf("bad header")

```

### GoTemplateFuncMap
```go
GoTemplateFuncMap = htmltemplate.FuncMap{
	"b64enc": tmpl_b64enc,
	"b64dec": tmpl_b64dec,

	"format_size": FormatSizeInByte,
	"inc":         tmpl_inc,
	"add":         tmpl_add,
	"title":       tmpl_title,
	"lower":       tmpl_lower,
	"upper":       tmpl_upper,
	"time_fmt":    tmpl_time_fmt,
	"now":         tmpl_now,
	"join":        tmpl_join,
	"raw_html": func(html string) htmltemplate.HTML {
		return htmltemplate.HTML(html)
	},
	"unsafe_raw_html": func(html string) htmltemplate.HTML {
		return htmltemplate.HTML(html)
	},
	"if_ie": func() htmltemplate.HTML {
		return htmltemplate.HTML("<!--[if IE]>")
	},
	"end_if_ie": func() htmltemplate.HTML {
		return htmltemplate.HTML("<![endif]-->")
	},
	"truncatechars": func(length int, in string) htmltemplate.HTML {
		return htmltemplate.HTML(ChunkString(in, length)[0])
	},
	"cycle": func(idx int, vals ...string) htmltemplate.HTML {
		_idx := idx % len(vals)
		return htmltemplate.HTML(vals[_idx])
	},
	"replace": func(data, old, new string) htmltemplate.HTML {
		o := strings.ReplaceAll(data, old, new)
		return htmltemplate.HTML(o)
	},
	"contains":       tmpl_contains,
	"slice_contains": tmpl_slice_contains,
	"int_range":      tmpl_int_range,
	"basename":       tmpl_basename,
	"dirname":        tmpl_dirname,
	"regex_search":   tmpl_regex_search,
	"regex_replace":  tmpl_regex_replace,
	"to_yaml":        tmpl_toyaml,
	"to_nice_yaml":   tmpl_to_niceyaml,
	"to_json":        tmpl_tojson,
	"indent":         tmpl_indent,
	"nindent":        tmpl_nindent,
}

```
Common usefull go html template funcs

### GoTextTemplateFuncMap
```go
GoTextTemplateFuncMap = template.FuncMap{
	"split":          tmpl_split,
	"cat":            tmpl_cat,
	"b64enc":         tmpl_b64enc,
	"b64dec":         tmpl_b64dec,
	"format_size":    FormatSizeInByte,
	"inc":            tmpl_inc,
	"add":            tmpl_add,
	"title":          tmpl_title,
	"lower":          tmpl_lower,
	"upper":          tmpl_upper,
	"time_fmt":       tmpl_time_fmt,
	"now":            tmpl_now,
	"join":           tmpl_join,
	"truncatechars":  tmpl_truncatechars,
	"cycle":          tmpl_cycle,
	"replace":        tmpl_replace,
	"contains":       tmpl_contains,
	"slice_contains": tmpl_slice_contains,
	"int_range":      tmpl_int_range,
	"basename":       tmpl_basename,
	"dirname":        tmpl_dirname,
	"to_yaml":        tmpl_toyaml,
	"to_nice_yaml":   tmpl_to_niceyaml,
	"to_json":        tmpl_tojson,
	"indent":         tmpl_indent,
	"nindent":        tmpl_nindent,
	"regex_search":   tmpl_regex_search,
	"regex_replace":  tmpl_regex_replace,
	"make_slice":     tmpl_makeslice,
}

```
Common func for go text template

### MaskCredentialPattern
```go
MaskCredentialPattern *regexp.Regexp = regexp.MustCompile(`(?i)(password|token|pass|passkey|secret|secret_key|access_key|PAT|AUTHORIZATION: Basic |Authorization: Basic |Authorization: Bearer |AUTH=)([:=]{1,1})[\s]*[^\s]+`)

```
MaskCredential RegexPattern



## Functions
### Func AddFilePart
```go
func AddFilePart(w *multipart.Writer, fieldname, filename string) error
```
Helper to stream file content into the multipart writer

### Func Assert
```go
func Assert(cond bool, msg string, fatal bool) bool
```

### Func AssertInt64ValueForMap
```go
func AssertInt64ValueForMap(input map[string]any) map[string]any
```

### Func Basename
```go
func Basename(fileName, ext string) string
```
Basename -

### Func BcryptCheckPasswordHash
```go
func BcryptCheckPasswordHash(password, hash string) bool
```
BcryptCheckPasswordHash validate password against its bcrypt hash

### Func BcryptHashPassword
```go
func BcryptHashPassword(password string, cost int) (string, error)
```
BcryptHashPassword return bcrypt hash for a given password

### Func BlockInFile
```go
func BlockInFile(filename string, upper_bound_pattern, lower_bound_pattern []string, marker []string, replText string, keepBoundaryLines bool, backup bool, start_line int, extraArgs ...map[string]any) (oldBlock string, start, end int, matchedPattern [][]string)
```
extraArg is optional but currently only accept one map[string]any.
The key would be a extra feature to control the behaviour As of now key:
insertIfNotFound => bool | controll if we do insert block if no block found.
Default is true

### Func CamelCaseToWords
```go
func CamelCaseToWords(s string, stripEdges bool) []string
```
CamelCaseToWords converts a camel case string into a list of words.

### Func CheckCertExpiry
```go
func CheckCertExpiry(address string, daysThreshold int) (bool, error)
```
CheckCertExpiry takes a domain address (e.g., "example.com:443") and a
threshold in days. It returns true if the certificate expires within that
threshold.

### Func CheckErr
```go
func CheckErr(err error, location string)
```

### Func CheckErrNonFatal
```go
func CheckErrNonFatal(err error, location string) error
```

### Func CheckNonErrIfMatch
```go
func CheckNonErrIfMatch(err error, ptn, location string) error
```

### Func ChunkString
```go
func ChunkString(s string, chunkSize int) []string
```
ChunkString - Break a strings into a chunk of size chunkSize

### Func CloneSliceOfMap
```go
func CloneSliceOfMap(a []any) (output []any)
```
CloneSliceOfMap

### Func ComputeHash
```go
func ComputeHash(plainText string, salt []byte) string
```
ComputeHash calcuate sha512 from a plaintext and salt

### Func ConvertInterface
```go
func ConvertInterface(value any) any
```
Function to recursively convert any to JSON-compatible types

### Func ConvertListIfaceToListStr
```go
func ConvertListIfaceToListStr(in any) []string
```
Function to convert any => list string

### Func ConvertStruct2Map
```go
func ConvertStruct2Map[T any](t T) ([]string, map[string]any)
```
Take a struct and convert into a map[string]any - the key of the map is the
struct field name, and the value is the struct field value.

This is useful to pass it to the gop template to render the struct value

### Func Copy
```go
func Copy(srcFile, dstFile string, opts ...*os.FileMode) error
```
Copy - copy file. Destination if exists then will be overriden. Preserves
source file mode unless overridden via options.

### Func CopyDirectory
```go
func CopyDirectory(scrDir, dest string) error
```
CopyDirectory copy the content of src => dest. Both src and dest dir need to
exists

### Func CopySymLink
```go
func CopySymLink(source, dest string) error
```

### Func CreateCompEncArchive
```go
func CreateCompEncArchive(source, outputPath any, options *CompEncOptions) error
```
CreateCompEncArchive creates an archive with streaming support for
stdin/FIFOs Accepts either a string or io.ReadCloser for sources If source
is "-" or a FIFO file, reads from stdin/fifo

### Func CreateDecryptionReader
```go
func CreateDecryptionReader(r io.Reader, password string) (io.Reader, error)
```
CreateDecryptionReader return a decryption reader (GCM mode)

### Func CreateDirTree
```go
func CreateDirTree(srcDirpath, targetRoot string) error
```
CreateDirTree take the directory structure from the source and create it in
the target. Path should be absolute path. They should not overlap to avoid
recursive loop

### Func CreateEncryptionWriter
```go
func CreateEncryptionWriter(w io.Writer, password string) io.WriteCloser
```
CreateEncryptionWriter returns io.WriteCloser so callers can close it.
This is GCM mode (highly secure)

### Func CreateIfNotExists
```go
func CreateIfNotExists(dir string, perm os.FileMode) error
```

### Func CreateTarball
```go
func CreateTarball(sources interface{}, outputPath any, options *TarOptions) error
```
CreateTarball accepts either a string or []string (same as your original)
and handles unix special files (block/char devices, fifos, sockets) when
creating the tar. If outputPath is "-" then write to stdout.

### Func CreateZipArchive
```go
func CreateZipArchive(sources interface{}, outputPath string, options *ZipOptions) error
```
CreateZipArchive creates a ZIP archive from: - sourceDir: a directory path
(string) - sources: multiple file/directory paths ([]string)

### Func Curl
```go
func Curl(method, url, data, savefilename string, headers []string, custom_client *http.Client, curlOpt ...*CurlOpt) (string, error)
```
Make a HTTP request to url and get data. Emulate the curl command. Take the
env var CURL_DEBUG - set to 'yes' if u need more debugging. CA_CERT_FILE,
SSL_KEY_FILE, SSL_CERT_FILE correspondingly if required

To ignore cert check set INSECURE_SKIP_VERIFY to yes

data - set it to empty string if you do not need to send any data.

savefilename - if you do not want to save to a file, set it to empty string

headers - Same as header array it is a list of string with : as separator.
Eg. []string{"Authorization: Bearer <myToken>"}

custom_client - if you want more option, create your own http/Client and
then setup the way you want and pass it here. Otherwise give it nil

If the value has @ it will be interpreted as fileField - like -F
"maven2.asset2=@/absolute/path/to/the/local/file/product-1.0.0.jar;type=application/java-archive"

Note the error return will not be nil if server returncode is not 2XX - it
will have the first status code in it string so by checking err you can see
the server response code.

Example to use cutom client is to make session aware using cookie jar

     import "golang.org/x/net/publicsuffix"
     jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})

    	client := http.Client{
    	  Jar:     jar,
    	  Timeout: time.Duration(_timeout) * time.Second,
     }

### Func CustomJsonMarshal
```go
func CustomJsonMarshal(v any) ([]byte, error)
```
Custom JSON marshalling function

### Func CustomJsonMarshalIndent
```go
func CustomJsonMarshalIndent(v any, indent int) ([]byte, error)
```

### Func Decrypt
```go
func Decrypt[T string | []byte](data, password T, cfg *EncryptionConfig) (T, error)
```
Decrypt decrypts a versioned encrypted base64 string. If data is string,
assume it is base64 encoded output of the Encrypt Password can be string
or []byte. Return type based on the encryption config OutputFmt, if it is
string then return as string, otherwise []byte

### Func DecryptFile
```go
func DecryptFile(inFile, outFile any, password string, encMode EncryptMode) error
```
Utility functions DecryptFile will decrypt file. Assume it is encrypted
using EncryptFile func. They uses CTR mode suitable for large files

### Func Decrypt_v0
```go
func Decrypt_v0(ciphertextBase64 string, key string) (string, error)
```
AES decrypt a ciphertext base64 encoded string

### Func Encrypt
```go
func Encrypt[T string | []byte, T2 string | []byte](data T, password T2, cfg *EncryptionConfig) (T, error)
```
Encrypt encrypts text using password-derived key with versioning. Depending
on EncryptionConfig field OutputFmt; if string then return base64 encoded of
the encrypted otherwise return raw []byte

### Func EncryptFile
```go
func EncryptFile(inFile, outFile any, password string, encMode EncryptMode) error
```
EncryptFile will encrypt file or an io.ReadCloser. Extract using DecryptFile
func. They uses CTR mode suitable for large files Output can be a file path
or io.Writer

### Func Encrypt_v0
```go
func Encrypt_v0(text, key string) (string, error)
```
AES encrypt a string. Output is cipher text base64 encoded. Old and weak
version. Keep here for compatibility

### Func Exists
```go
func Exists(filePath string) bool
```

### Func ExtractCompEncArchive
```go
func ExtractCompEncArchive(inputPath, outputPath any, options *CompEncOptions) error
```
ExtractCompEncArchive extracts a cpio archive with support for compression
and encryption If inputPath is "-", reads from stdin

### Func ExtractLineInLines
```go
func ExtractLineInLines(blocklines []string, start, line, end string) [][]string
```
ExtractLineInLines will find a line match a pattern with capture (or not).
The pattern is in between a start pattern and end pattern to narrow down

search range. Return the result of FindAllStringSubmatch func of the match
line

This is simpler as it does not support multiple pattern as a marker like the
other func eg ExtractTextBlockContains so input should be small and pattern
match should be unique. Use the other function to devide it into small range
and then use this func.

start and line can be the same pattern. Same as line and end; it will return
the match of start (or end) pattern

### Func ExtractTarball
```go
func ExtractTarball(tarballPath any, extractDir string, options *TarOptions) error
```
ExtractTarball extracts a tarball with optional decompression and
decryption. Compression format is auto-detected from magic bytes when
options.Format is CompressionNone (or options is nil with UseCompression
true). If tarballPath is "-" then read from stdin.

### Func ExtractTextBlock
```go
func ExtractTextBlock(filename string, start_pattern, end_pattern []string) (block string, start_line_no int, end_line_no int, datalines []string)
```
ExtractTextBlock extract a text from two set regex patterns. The text
started with the line matched start_pattern and when hit the match for
end_pattern it will stop not including_endlines

### Func ExtractTextBlockContains
```go
func ExtractTextBlockContains(filename string, upper_bound_pattern, lower_bound_pattern []string, marker []string, start_line int) (block string, start_line_no int, end_line_no int, datalines []string, matchedPatterns [][]string)
```
Extract a text block which contains marker which could be an int or a list
of pattern. if it is an int it is the line number.

First we get the text from the line number or search for a match to the
upper pattern. If we found we will search down for the marker if it is
defined, and when found, search for the lower_bound_pattern.

# The marker should be in the middle

Return the text within the upper and lower, but not including the lower
bound. Also return the line number range and full file content as datalines

upper and lower is important; you can ignore marker by using a empty
[]string{}

### Func ExtractZipArchive
```go
func ExtractZipArchive(zipPath, extractDir string, options *ZipOptions) error
```
ExtractZipArchive extracts a ZIP archive with optional decryption

### Func FileExists
```go
func FileExists(name string) (bool, error)
```
FileExists test if file 'name' exists

### Func FileExistsV2
```go
func FileExistsV2(name string) error
```
This is short version of FileExists - Return stat error so user can use it
more. If nil then it exists otherwise It is meant to be use in Ternary like
Ternary(FileExistsV2(path) == nil, "something", "somethingelse")

### Func FileGrep
```go
func FileGrep(filePaths, patternStr, excludePtnStr string, outputMatchOnly, inverse bool) (foundMatch bool)
```
Grep files in a dir. Used it when you know files are small enough like less
than 100MB. For large file to grep you have to use the GrepStream function

### Func FileNameWithoutExtension
```go
func FileNameWithoutExtension(fileName string) string
```
return strings.TrimSuffix(fileName, filepath.Ext(fileName))

### Func FileTouch
```go
func FileTouch(fileName string) error
```
FileTouch is similar the unix command 'touch'. If file does not exists,
an empty file will be created

### Func FormatSizeInByte
```go
func FormatSizeInByte(size int64) string
```

### Func GenRandomString
```go
func GenRandomString(n int) string
```
GenRandomString generates a random string with length 'n'

### Func GenSelfSignedKey
```go
func GenSelfSignedKey(keyfilename string)
```
Crypto utils

### Func GenerateLinuxRandom
```go
func GenerateLinuxRandom(max uint64) (uint64, error)
```
Generate a random number as uint64. Use linux /dev/random directly. This may
have better randomness?

### Func GenerateRandom
```go
func GenerateRandom(max uint64) uint64
```
GenerateRandom generate random number directly using /dev/random rather than
crypto lib Only support on Linux. On other platform it will call other func
to use crypto lib

### Func GenerateRandomBytes
```go
func GenerateRandomBytes(length int) (string, error)
```
Generate a number of bytes randomly - return base64 encoded string.

### Func GenerateX509Keypair
```go
func GenerateX509Keypair[T PrivateKeyConstraint](initialKey T, data map[string]any) (T, any, *x509.CertificateRequest)
```
Generate bunch of key type. Call it with empty key and select type you want
to generate, it will fill the value and turn back

### Func GetFirstValue
```go
func GetFirstValue[T, T1 any](x T, y T1) T
```

### Func Getenv
```go
func Getenv(key, fallback string) string
```

### Func GetenvBool
```go
func GetenvBool(key string, def bool) bool
```

### Func GoFindExec
```go
func GoFindExec(directories []string, path_pattern []string, callback func(filename string, info fs.FileInfo) error) error
```
GoFindExec take a list of directory paths and list of regex pattern to match
the file/dir name. If it matches then it call the callback function for that
file/dir path (relatively to the current working dir if your dir/file path
is relative path)

filetype is parsed from the directory prefix eg. file:// for file, dir://
for directory. It only return the file type for the corresponding path.

    Eg. GoFindExec([]string{"file://."},[]string{`.*`}, func(myfilepath) error {
    	println(myfilepath)
     return nil
    })

### Func GoTemplateFile
```go
func GoTemplateFile(src, dest string, data map[string]any, fileMode os.FileMode)
```
This func use text/template to avoid un-expected html escaping.

### Func GoTemplateString
```go
func GoTemplateString(srcString string, data any) string
```
This func use text/template to avoid un-expected html escaping.

### Func Grep
```go
func Grep[T string | *regexp.Regexp](input string, pattern T, outputMatchOnly bool, inverse bool) (out []string, matchedFound bool)
```
Grep a pattern in a text

### Func GrepStream
```go
func GrepStream[T string | *regexp.Regexp](input io.ReadCloser, pattern T, outputMatchOnly bool, inverse bool, outputPrefix, replace string) (matchedFound bool)
```
Grep a pattern in a stream of text. Just print meatches oout as they go.
Suitable for large file or stdin If input size > 1MB use this. If replace is
not empty then it does the replacement by line. Capture in the form $N will
be replaced as well.

### Func InsertItemAfter
```go
func InsertItemAfter[T any](slice []T, index int, item T) []T
```
InsertItemAfter inserts an item into a slice after a specified index

### Func InsertItemBefore
```go
func InsertItemBefore[T any](slice []T, index int, item T) []T
```
InsertItemBefore inserts an item into a slice before a specified index

### Func InterfaceToStringList
```go
func InterfaceToStringList(in []any) []string
```

### Func InterfaceToStringMap
```go
func InterfaceToStringMap(in map[string]any) map[string]string
```

### Func IsBase64DecodeError
```go
func IsBase64DecodeError(err error) bool
```

### Func IsBinaryFile
```go
func IsBinaryFile(filePath string) (bool, error)
```

### Func IsBinaryFileSimple
```go
func IsBinaryFileSimple(filePath string) (bool, error)
```

### Func IsFIFO
```go
func IsFIFO(path string) (bool, error)
```

### Func IsNamedPipe
```go
func IsNamedPipe(path string) (bool, fs.FileInfo)
```

### Func ItemExists
```go
func ItemExists[T comparable](item T, set map[T]any) bool
```
Check if key of type T exists in a map[T]any

### Func JsonByteToMap
```go
func JsonByteToMap(jsonByte []byte) map[string]any
```
JsonByteToMap take a json as []bytes and decode it into a map[string]any.

### Func JsonDump
```go
func JsonDump(obj any, indent string) string
```

### Func JsonDumpByte
```go
func JsonDumpByte(obj any, indent string) []byte
```

### Func JsonToMap
```go
func JsonToMap(jsonStr string) map[string]any
```
JsonToMap take a json string and decode it into a map[string]any. Note that
the value if numeric will be cast it to int64. If it is not good for your
case, use the func JsonByteToMap which does not manipulate this data

### Func LineInFile
```go
func LineInFile(filename string, opt *LineInfileOpt) (err error, changed bool)
```
Simulate ansible lineinfile module. There are some difference intentionaly
to avoid confusing behaviour and reduce complexbility. No option backref,
the default behaviour is yes.

### Func LineInLines
```go
func LineInLines(datalines []string, search_pattern string, replace string) (output []string)
```
Edit line in a set of lines using simple regex and replacement

### Func LoadConfigIntoEnv
```go
func LoadConfigIntoEnv(configFile string) (map[string]any, error)
```
LoadConfigIntoEnv load the json/yaml config file 'configFile' and export env
var - var name is the key and value is the json value

### Func LoadPrivateKeyFromPEM
```go
func LoadPrivateKeyFromPEM(filePath string) (crypto.PrivateKey, error)
```

### Func MakePassword
```go
func MakePassword(length int) string
```
MakePassword -

### Func MakeRandNum
```go
func MakeRandNum(max int) int
```
MakeRandNum -

### Func MakeRequest
```go
func MakeRequest(method string, config map[string]any, data []byte, jar *cookiejar.Jar) map[string]any
```
MakeRequest make a http request with method (POST or GET etc...). It support
sessions - if you have existing session stored in cookie jar then pass it to

the `jar` param otherwise a new cookie ja session will be created.

config has these keys:

- timeout - set the time out of time int. Default is 600 secs - url - the
URL that the request will be sent to - token - string - the Authorization
token if required. It will make the header 'Authorization' using the token
- headers - a map[string]string to pass any arbitrary reuqets headers Key :
Value

Return value is the response. If it is a json of type list then it will be
put into the key "results"

This is used to make API REST requests and expect response as json.
To download or do more general things, use the function Curl above instead

### Func MakeSalt
```go
func MakeSalt(length int8) (salt *[]byte)
```

### Func MapContainsKeys
```go
func MapContainsKeys[K comparable, V1, V2 any](main map[K]V1, sub map[K]V2) bool
```
MapContainsKeys is quick way to do set contains using map If main map has
keys set which contains all key sets of sub map then return true otherwise

### Func MapKeysToSlice
```go
func MapKeysToSlice[K comparable, T any](m map[K]T) []K
```
Similar to the python dict.keys()

### Func MapLookup
```go
func MapLookup[T any](m map[string]T, key string, default_val T) T
```
MapLookup search a key in a map and return the value if found, otherwise
return the default_val

### Func MarshalCSRPEM
```go
func MarshalCSRPEM(csr *x509.CertificateRequest) []byte
```

### Func MarshalPKCS8PrivatePEM
```go
func MarshalPKCS8PrivatePEM[T PrivateKeyConstraint](privKey T) ([]byte, error)
```

### Func MarshalPKIXPublicKeyPEM
```go
func MarshalPKIXPublicKeyPEM(pubKey any) ([]byte, error)
```

### Func MaskCredential
```go
func MaskCredential(inputstr string) string
```
Mask all credentials pattern

### Func Md5Sum
```go
func Md5Sum(key string) string
```

### Func MergeAttributes
```go
func MergeAttributes(a, b []any, action string) []any
```
Add or delete attrbs set in a to b. action can be 'add'; if it is empty it
will do a delete.

a and b is a list of map of items having two fields, key and value.

# If key does not exists in b and action is add - it will add it to b

# If key is matched found and

# If key is not nil and b will be updated or delete per action

If key is nil and value matched and action is not add - the item will be
removed

### Func Must
```go
func Must[T any](res T, err error) T
```
Must wraps two values pair with second one is an error, check if error is
nil then return the first, otherwise panic with error message

### Func MustOpenFile
```go
func MustOpenFile(f string) *os.File
```

### Func NewStreamDecryptReader
```go
func NewStreamDecryptReader(rc io.ReadCloser, password string) (io.ReadCloser, error)
```
NewStreamDecryptReader reads header and returns a reader that yields
plaintext. It validates per-frame HMACs and returns ErrMacMismatch if
tampered.

### Func NsToTime
```go
func NsToTime(ns int64) time.Time
```
NsToTime - Convert a nanoseconds number to time object

### Func ParseConfig
```go
func ParseConfig(configFile string) (map[string]any, error)
```
ParseConfig loads the json/yaml config file 'configFile' into a map json is
tried first and then yaml

### Func ParseJsonReqBodyToMap
```go
func ParseJsonReqBodyToMap(r *http.Request) map[string]any
```

### Func ParseJsonReqBodyToStruct
```go
func ParseJsonReqBodyToStruct[T any](r *http.Request) *T
```
ParseJSON parses the raw JSON body from an HTTP request into the specified
struct.

### Func ParseTimeRange
```go
func ParseTimeRange(durationStr, tz string) (time.Time, time.Time)
```
Given a duration string return a tuple of start time, end time satisfy the
duration. If duration string is dd/mm/yyyy hh:mm:ss - dd/mm/yyyy hh:mm:ss it
simply return two time object. If duration is like 15m then endtime is now,
start time is 15 minutes ago. This applies for all case if input is not
parsable

### Func ParseVarArgs
```go
func ParseVarArgs(args ...string) map[string]string
```
*
  - ParseVarArgs takes a variadic slice of strings and converts them into a
    map.
  - It assumes the pattern: [key1, value1, key2, value2, ...] *
  - If the number of arguments is odd, the last element is ignored (as it
    has no pair)
  - or you can handle it as a nil value depending on your preference.

### Func PickLinesInFile
```go
func PickLinesInFile(filename string, line_no, count int) (lines []string)
```
PickLinesInFile - Pick some lines from a line number with count. If count is
-1 pick to the end, -2 then to the end - 1 etc...

Line number started from 0

### Func PickLinesInFileV2
```go
func PickLinesInFileV2(filename string, line_no, count int) ([]string, error)
```
PickLinesInFileV2 - Pick some lines from a line number with count. If count
is negative like -1 pick to the end that is last line, -2 then to the last 2
lines etc..

# Line number started from 0

Uses bufio.Scanner for memory efficiency with large files.

### Func RandomHex
```go
func RandomHex(n int) (string, error)
```

### Func ReadFileToBase64Content
```go
func ReadFileToBase64Content(filename string) string
```

### Func ReadFileToLines
```go
func ReadFileToLines(filename string, cleanline bool) []string
```
ReadFileToLines will read a file and return content as a slice of lines. If
cleanline is true then each line will be trim and empty line will be removed

### Func ReadFirstLineWithPrefix
```go
func ReadFirstLineWithPrefix(filePath string, prefix []string) (firstLine string, temp_file, matchedPrefix string, err error)
```
ReadFirstLine read the first line in a file. Optimized for performance thus
we do not re-use PickLinesInFile Also return the reader to the caller if
caller need to

### Func RemoveDuplicate
```go
func RemoveDuplicate[T comparable](slice []T) []T
```
RemoveDuplicate remove duplicated item in a slice

### Func RemoveItem
```go
func RemoveItem(s []any, i int) []any
```
RemoveItem This func is depricated Use RemoveItemByIndex. Remove an item of
the index i in a slice

### Func RemoveItemByIndex
```go
func RemoveItemByIndex[T comparable](s []T, i int) []T
```
RemoveItemByIndex removes an item from a slice of any type. Using the index
of the item.

### Func RemoveItemByVal
```go
func RemoveItemByVal[T comparable](slice []T, item T) []T
```
RemoveItemByVal removes an item from a slice of any type

### Func ReplaceAllFuncN
```go
func ReplaceAllFuncN(re *regexp.Regexp, src []byte, repl func([]int, [][]byte) []byte, n int) ([]byte, int)
```
ReplaceAllFuncN extends regexp.Regexp to support count of replacements for
[]byte

### Func ReplacePattern
```go
func ReplacePattern[T string | *regexp.Regexp](input []byte, pattern T, repl string, count int) ([]byte, int)
```
Quickly replace. Normally if you want to re-use the regex ptn then better
compile the pattern first and used the standard lib regex replace func.
This only save u some small typing.

the 'repl' can contain capture using $1 or $2 for first group etc..

### Func RunDSL
```go
func RunDSL(dbc *sql.DB, sql string) map[string]any
```

### Func RunSQL
```go
func RunSQL(dbc *sql.DB, sql string) map[string]any
```
Run SELECT and return map[string]any{"result": []any, "error": error}

### Func RunSystemCommand
```go
func RunSystemCommand(cmd string, verbose bool) (output string)
```
RunSystemCommand run the command 'cmd'. It will use 'bash -c <the-command>'
thus requires bash installed On windows you need to install bash or mingw64
shell If command exec get error it will panic!

### Func RunSystemCommandV2
```go
func RunSystemCommandV2(cmd string, verbose bool) (output string, err error)
```
RunSystemCommandV2 run the command 'cmd'. It will use 'bash -c
<the-command>' thus requires bash installed On windows you need to install
bash or mingw64 shell The only differrence with RunSystemCommand is that
it returns an error if error happened and it wont panic When no error,
it return output as the command stdout. When error happened, it return
a json string with field { "Stdout": stdout, "Stderr": stderr, "Cmd":
<the command u ran> },

### Func RunSystemCommandV3
```go
func RunSystemCommandV3(command *exec.Cmd, verbose bool) (output string, err error)
```
RunSystemCommandV3. Unlike the other two, this one you craft the exec.Cmd
object and pass it to this function This allows you to customize the
exec.Cmd object before calling this function, eg, passing more env vars into
it like command.Env = append(os.Environ(), "MYVAR=MYVAL"). You might not
need bash to run for example but run directly In case of error, the output
is a json string with field Stdout and Stderr populated.

### Func SearchPatternListInStrings
```go
func SearchPatternListInStrings(datalines []string, pattern []string, start_line, max_line, direction int) (found_marker bool, start_line_no int, matchedPatterns []string)
```
Given a list of string of regex pattern and a list of string, find the
coninuous match in that input list and return the start line of the match
and the line content

max_line defined the maximum line to search; set to 0 to use the len of
input lines which is full

start_line is the line to start searching; set to 0 to start from begining.
start_line should be smaller than max_line

direction is the direction of the search -1 is upward; otherwise is down.
If it is not 0 then the value is used for the step jump while searching eg.
1 for every line, 2 for every

2 lines, -2 is backward every two lines

If found match return true, the line no we match and the line content.

### Func SearchReplaceFile
```go
func SearchReplaceFile[T string | *regexp.Regexp](filename string, ptn T, repl string, count int, backup bool) int
```
Same as ReplacePattern but do regex search and replace in a file

### Func SearchReplaceString
```go
func SearchReplaceString[T string | *regexp.Regexp](instring string, ptn T, repl string, count int) string
```
Same as ReplacePattern but operates on string rather than []byte

### Func SendMail
```go
func SendMail(from string, to []string, subject, body string, attachmentPaths []string, smtpServerInfo, username, password string, useSSL bool) error
```
SendMail sends an email with a text body and multiple attachments over
SSL/TLS if requested

### Func Sha1Sum
```go
func Sha1Sum(in string) string
```

### Func Sha256Sum
```go
func Sha256Sum(in string) string
```

### Func Sha256SumFile
```go
func Sha256SumFile(filePath string) string
```

### Func Sha512Sum
```go
func Sha512Sum(in string) string
```

### Func Sleep
```go
func Sleep(duration string)
```

### Func SliceContainsAnyItem
```go
func SliceContainsAnyItem[K comparable](main []K, sub []K) bool
```
SliceContainsAnyItem return true if main slice contains any items in sub
slice

### Func SliceContainsItems
```go
func SliceContainsItems[K comparable](main []K, sub []K) bool
```
SliceContainsItems return true if main slice contains all items in sub slice

### Func SliceMap
```go
func SliceMap[T, V any](ts []T, fn func(T) *V) []V
```

### Func SliceToMap
```go
func SliceToMap[T comparable](slice []T) map[T]any
```
SliceToMap convert a slice of any comparable into a map which can set the
value later on

### Func SliceToMap2
```go
func SliceToMap2[T comparable, V any](slice [][]T, fn func(in []T, out map[T]V) (V, bool)) map[T]V
```
Slice2ToMap folds [][]T into map[T]V.

Contract:
  - each inner slice must have length >= 2
  - fn may be nil to use default behavior
  - fn may read or mutate out
  - return (v, true) to set, (_, false) to skip

### Func SliceWalk
```go
func SliceWalk[T, V any](ts []T, fn func(T) *V) []V
```
Take a slice and a function return new slice with the value is the result of
the function called for each item Similar to list walk in python. To exclude
the result, return nil from your func

### Func SplitFirstLine
```go
func SplitFirstLine[T string | []byte](data T) (T, T)
```
SplitFirstLine return the first line from a text block. Line ending can be
unix based or windows based. The rest of the block is return also as the
second output

### Func SplitTextByPattern
```go
func SplitTextByPattern(text, pattern string, includeMatch bool) []string
```
SplitTextByPattern splits a multiline text into sections based on a regex
pattern.

If includeMatch is true, the matching lines are included in the result.

pattern should a multiline pattern like `(?m)^Header line.*`

### Func StringMapToAnyMap
```go
func StringMapToAnyMap(m map[string]string) map[string]any
```
StringMapToAnyMap converts map[string]string to map[string]any

### Func Ternary
```go
func Ternary[T any](expr bool, x, y T) T
```
Emulate the Ternary in other languages but only support simple form so
nobody can abuse it

### Func Unzip
```go
func Unzip(src, dest string) error
```
DEPRICATED - Should use the ExtractZipArchive Unzip will unzip the 'src'
file into the directory 'dest' This version is pure go - so no need to have
the zip command.

### Func Upload
```go
func Upload(client *http.Client, url string, values map[string]io.Reader, mimetype map[string]string, headers map[string]string) (err error)
```
Prepare a form that you will submit to that URL.

client if it is nil then new http client will be used

url is the url the POST request to

values is a map which key is the postform field name. The value of the map
should be any io.Reader to read data from like *os.File to post attachment
etc..

mimetype if set which has the key is the file name in the values above,
and the value is the mime type of that file

headers is extra header in the format key/value pair. note the header
'Content-Type' should be automatically added

Note:

This is not working for report portal (RP) basically golang somehow
send it using : Content type 'application/octet-stream' (or the server
complain about that not supported). There are two parts each of them has
different content type and it seems golang implementation does not fully
support it? (the jsonPaths must be application-json). For whatever it is,
even the header printed out correct - server complain. Curl work though so
we will use curl for now I think golang behaviour is correct it should be
'application/octet-stream' for the file part, but the RP java server does
not behave.

So we add a manual set header map in for this case

### Func ValidateInterfaceWithStringKeys
```go
func ValidateInterfaceWithStringKeys(val any) (any, error)
```
Pass an interface, return same interface if they are map of string to
interface or list of string as key

### Func VerifyHash
```go
func VerifyHash(password string, passwordHashString string, saltLength int) bool
```
VerifyHash validate password against its hash string created by ComputerHash

### Func ZipDecrypt
```go
func ZipDecrypt(filePath ...string) error
```
DEPRICATED Note that we implement much more secure and complete Zip in func
CreateZipArchive, ExtractZipArchive funcs Keep this here for compatibility
only ZipDecrypt decrypt the zip file. First arg is the file name, second is
the key used to encrypt it. Requires the command 'unzip' installed

### Func ZipEncript
```go
func ZipEncript(filePath ...string) string
```
DEPRICATED Note that we implement much more secure and complete Zip in func
CreateZipArchive, ExtractZipArchive funcs Keep this here for compatibility
only Encrypt zip files. The password will be automtically generated and
return to the caller Requires command 'zip' available in the system.
Note zip encryption is very weak. Better to use 7zip encryption instead



## Types
### Type AppConfigProperties
```go
type AppConfigProperties map[string]string
```

### Functions

```go
func ReadPropertiesFile(filename string) (AppConfigProperties, error)
```
ReadPropertiesFile read from a file with content format like 'key=value' and
return AppConfigProperties which is a map[string]string


```go
func ReadPropertiesString(inputString string) (AppConfigProperties, error)
```
ReadPropertiesString read from a string with format like 'key=value' and
return AppConfigProperties which is a map[string]string




### Type ArrayFlags
```go
type ArrayFlags []string
```
ArrayFlags to be used for standard golang flag to store multiple values.
Something like -f file1 -f file2 will store list of file1, file2 in the var
of this type. Example:

var myvar ArrayFlags

flag.Var(&myvar, "f", "File names")

### Methods

```go
func (i *ArrayFlags) Set(value string) error
```


```go
func (i *ArrayFlags) String() string
```




### Type Base64DecodeError
```go
type Base64DecodeError struct {
	Msg string
	Err error
}
```
Custom error type section

### Methods

```go
func (e *Base64DecodeError) Error() string
```


```go
func (e *Base64DecodeError) Unwrap() error
```




### Type CompEncOptions
```go
type CompEncOptions struct {
	UseCompression    bool
	CompressionLevel  int
	Encrypt           bool
	Password          string
	EncryptMode       EncryptMode // "GCM" or "CTR"
	OverwriteExisting bool
}
```
CompEncOptions holds configuration for cpio archive creation

### Functions

```go
func NewCompEncOptions() *CompEncOptions
```
NewCompEncOptions returns default options for cpio creation



### Methods

```go
func (zo *CompEncOptions) WithCompression(enabled bool) *CompEncOptions
```


```go
func (zo *CompEncOptions) WithCompressionLevel(level int) *CompEncOptions
```


```go
func (zo *CompEncOptions) WithEncrypt(enabled bool) *CompEncOptions
```


```go
func (zo *CompEncOptions) WithEncryptMode(m EncryptMode) *CompEncOptions
```


```go
func (zo *CompEncOptions) WithOverwriteExisting(s bool) *CompEncOptions
```


```go
func (zo *CompEncOptions) WithPassword(pass string) *CompEncOptions
```




### Type CompressionFormat
```go
type CompressionFormat int
```
CompressionFormat selects the compression algorithm

### Constants
### CompressionZstd, CompressionGzip, CompressionBzip2, CompressionXz, CompressionNone
```go
CompressionZstd CompressionFormat = iota // default, existing behaviour

CompressionGzip // .tar.gz / .tgz

CompressionBzip2 // .tar.bz2  (read-only; bzip2 stdlib has no writer)

CompressionXz // .tar.xz

CompressionNone // no compression


```




### Type CurlOpt
```go
type CurlOpt struct {
	// The form fields. Similar the option curl -F "key=value" -F "filename=@filepath"
	FormFields map[string]string
	// If set then enable Basic auth - curl -u "username:password"
	User               string
	Password           string
	CaCertFile         string
	SslKeyFile         string
	SslCertFile        string
	InsecureSkipVerify bool
	FileMode           os.FileMode
	Debug              string
}
```
CurlOpt struct to fine tune Curl command beahaviour


### Type EncryptMode
```go
type EncryptMode string
```
AES CTR IO

### Constants
### EncryptModeCTR
```go
EncryptModeCTR EncryptMode = "AESC1CTR"

```

### EncryptModeGCM
```go
EncryptModeGCM EncryptMode = "GCM"

```




### Type EncryptionConfig
```go
type EncryptionConfig struct {
	Version  byte
	SaltSize int
	KeySize  int
	KDF      KDFType

	// Scrypt
	ScryptN int
	ScryptR int
	ScryptP int

	// Argon2id
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
	OutputFmt    string // string or raw; string we will base64 encoded it, raw we keep encrypted data as is
}
```
EncryptionConfig holds config for encryption

### Functions

```go
func DefaultEncryptionConfig() *EncryptionConfig
```
DefaultEncryptionConfig returns secure defaults


```go
func NewEncConfigForVersion(version byte) (*EncryptionConfig, error)
```




### Type EncryptionWriter
```go
type EncryptionWriter struct {
	// contains filtered or unexported fields
}
```
Placeholder for your encryption implementation

### Methods

```go
func (ew *EncryptionWriter) Close() error
```


```go
func (ew *EncryptionWriter) Write(p []byte) (n int, err error)
```




### Type ExecOpts
```go
type ExecOpts struct {
	Args  []string
	Envs  map[string]string
	Debug bool
}
```
ExecOpts is used to pass advanced Exec Options


### Type KDFType
```go
type KDFType string
```

### Constants
### KDFArgon2id, KDFScrypt
```go
KDFArgon2id KDFType = "argon2id"
KDFScrypt KDFType = "scrypt"

```




### Type LineInfileOpt
```go
type LineInfileOpt struct {
	//string marker to insert the line after if regex or search string not found
	Insertafter string
	//string marker to insert the line above if regex or search string not found
	Insertbefore string
	// Line content - may contains capture group like $1
	Line string
	// Line number, if set just replace that line; ignore all options
	LineNo int
	Path   string
	// regex to match a line, if set and match line will be replaced. If not match line will be added based on location (after or before above)
	Regexp string
	// Same as regex but search raw string
	Search_string string
	// Default is 'present'. Set to absent to remove lines. This case regex or search string needed and all lines matched will be removed. Ignore all other opts
	State string
	// Backup the file or not. Default is false
	Backup bool
	// Keep backup files after number of days -
	KeepBackupDays int
	// Action for all pattern if set to true, otherwise only one line. Default is false
	ReplaceAll bool
}
```

### Functions

```go
func NewLineInfileOpt(opt *LineInfileOpt) *LineInfileOpt
```




### Type PrivateKeyConstraint
```go
type PrivateKeyConstraint interface {
	*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
	Public() crypto.PublicKey
}
```
PrivateKeyConstraint matches the core Go private key types and ensures they
satisfy the crypto.Signer interface.


### Type SshExec
```go
type SshExec struct {
	// Auto generated per each spawn
	SessionDir string
	SshClient  *ssh.Client
	// Remote host name to exec the gomod or command. Required
	SshExecHost   string
	SshPort       string
	SshKeyFile    string
	SshCommonOpts string
	SshKnownHost  string
	SshUser       string
	// This will be auto generated and re-use per each NewSshExec instantiation
	SshConfigFilePath    string
	SshConfigFileContent string
	// Directory name which contains the package main and compilable into a exec file to exec on remote. See ExecGoMod func for more
	GoModDir string
	// Default is 0 that is disable CGO_ENABLED=0 when compiling go source
	CgoEnabled string
	GoProxy    string
	// This is used when we fetch external resource to build go src; if your web server requires auth, set it
	HttpHeaders []string
	// Use it to pass more options for Curl to fetch, example Basic Auth can be set using CurlOpt
	CurlOpt *CurlOpt
}
```
The controller hosts can be linux/nix or windows with git bash installed.
The remote hosts should be only nix OS with sshd running In theory remote
hosts with git bash and sshd server installed should be ok

### Functions

```go
func NewSshExec(s *SshExec) (*SshExec, error)
```
NewSshExec initializes a new SshExec and establishes the SSH connection


```go
func NewSshExecUseCLI(s *SshExec) (*SshExec, error)
```



### Methods

```go
func (s *SshExec) Close()
```
Clean up the object


```go
func (s *SshExec) Connect() error
```


```go
func (s *SshExec) CopyAndExec(exebin, remoteWorkDir string, keepAndReuseExec bool, execArgs ...string) (out string, err error)
```
CopyAndExec copies a local or a binary from a url to remoteWorkDir, and exec
that bin in remoteWorkDir with execArgs if exebin started with http(s)://
then download it locally first before copy to remote If remoteWorkDir
is empty string, it will created as temporary and clean up later on If
remoteWorkDir is preset then the binary in there be checked - if it exists
and same sha256 with local, no copy will be done remoteWorkdir can be
relative or absolute path if provided Return the remoteWorkDir Path


```go
func (s *SshExec) CopyAndExecUseCLI(exebin, remoteWorkDir string, keepAndReuseExec bool, execArgs ...string) (out string, err error)
```
Copy a local or a binary from a url to remoteWorkDir, and exec that bin in
remoteWorkDir with execArgs if exebin started with http(s):// then download
it locally first before copy to remote If remoteWorkDir is empty string,
it will created as temporary and clean up later on If remoteWorkDir is
preset then the binary in there be checked - if it exists and same sha256
with local, no copy will be done


```go
func (s *SshExec) CopyAndExecWithOpts(exebin, remoteWorkDir string, keepAndReuseExec bool, execOpt ExecOpts) (out string, err error)
```
CopyAndExecWithOpts copies a local or a binary from a url to remoteWorkDir,
and exec that bin in remoteWorkDir with execOpt if exebin started with
http(s):// then download it locally first before copy to remote If
remoteWorkDir is empty string, it will created as temporary and clean up
later on If remoteWorkDir is preset then the binary in there be checked - if
it exists and same sha256 with local, no copy will be done remoteWorkdir can
be relative or absolute path if provided Return the remoteWorkDir Path


```go
func (s *SshExec) CopyDir(remotePath string, srcPaths ...string) (out string, err error)
```
CopyDir copies local dir/files to remote using a streaming tar/zstd approach
via SSH Session. Requires remote host has tar and zstd utils installed.


```go
func (s *SshExec) CopyDirUseCLI(remotePath string, srcPaths ...string) (out string, err error)
```
Copy local dir/files to remote. The remotePath does not have to exist,
in that case it will be created. The dirname of srcPaths is preserved if it
points to a directory. It can be a multiple file paths which will be copied
to remotePath/<file-name>

Use ssh exec and tar for compressing and extracting. Requires remote host
has tar and zstd utils installed

If remotePath is empty a random tmp dir would be created and value return to
be used for the next command


```go
func (s *SshExec) CopyFile(remotePath string, srcPaths ...string) (out string, err error)
```
CopyFile copies file(s) to remote using SFTP. Filename will be retained.
remotePath is a directory and will be created if it does not exist.
If srcPath starts with http then the file will be downloaded first before
copying Return the remote directory path


```go
func (s *SshExec) CopyFileUseCLI(remotePath string, srcPaths ...string) (out string, err error)
```
Copy file(s) to remote. Filename will be retained. remotePath is a directory
and be created if not exists Use scp in the OS. Each file will spawn one scp
thus if you copy multiple files/dirs, it is better to use the func CopyDir
instead as it will use pipe to remote. If remotePath is empty a random tmp
dir would be created and value return to be used for the next command


```go
func (s *SshExec) Exec(commands string) (out string, err error)
```
Exec a command on remote host hostname via ssh. Multiline command supported


```go
func (s *SshExec) ExecGoMod(resourceUrl, gomodName, remoteWorkDir string, args ...string) (out string, err error)
```
Exec a gomod at the remote hostname. resourceUrl is the Url to fetch the
go source code project. It will fetch resourceUrl if required locally and
compile it, then copy the cli to remote end exec it with args

resourceUrl -> If it start with wget+ then assume it is download url.
We strip off the 'wget+' to get the url The last filename should be a tar
ball and no root directory (that is the go.mod is at the root dir). We will
download the file, extract it to a temp dir and chdir into it before build.

# If it is normal directory path then it will use it directly for compile the
cli

All other case will be assumed as a git resource Url, See man git-clone for
more. It will be passed to git clone command as is.

The directory structure should be a valid go mod dir (it has go.mod and
go.sum) a list of dirs named <gomodName> with a main.go compilable to a
binary. If this is empty the the root dir will be used. The binary name
is the go mod name when you run go mod init <name> the option GoModDir is
the directory path leading to the go.mod and go.sum file, default empty,
that is we use the root dir The args will be parsed to the execution

It will fetch the resource, compile it and copy to remote to exec. Currently
only Linux remote hosts supported

Return command output and error


```go
func (s *SshExec) ExecGoModUseCLI(resourceUrl, gomodName, remoteWorkDir string, args ...string) (out string, err error)
```
Exec a gomod at the remote hostname. resourceUrl is the Url to fetch the
go source code project. It will fetch resourceUrl if required locally and
compile it, then copy the cli to remote end exec it with args

resourceUrl -> If it start with wget+ then assume it is download url.
We strip off the 'wget+' to get the url The last filename should be a tar
ball and no root directory (that is the go.mod is at the root dir). We will
download the file, extract it to a temp dir and chdir into it before build.

# If it is normal directory path then it will use it directly for compile the
cli

All other case will be assumed as a git resource Url, See man git-clone for
more. It will be passed to git clone command as is.

The directory structure should be a valid go mod dir (it has go.mod and
go.sum) a list of dirs named <gomodName> with a main.go compilable to a
binary. If this is empty the the root dir will be used. The binary name
is the go mod name when you run go mod init <name> the option GoModDir is
the directory path leading to the go.mod and go.sum file, default empty,
that is we use the root dir The args will be parsed to the execution

It will fetch the resource, compile it and copy to remote to exec. Currently
only Linux remote hosts supported

Return command output and error


```go
func (s *SshExec) ExecUseCLI(commands string) (out string, err error)
```
Exec a command on remote host hostname via ssh. Multiline command supported


```go
func (s *SshExec) Fetch(dest string, remoteSrc ...string) (out string, err error)
```
Fetch (Download) from remote to local. If remote is a file, download the
file. If a dir, download the whole dir. The dest dir is local dir and its
contents are remote dir (if remote is a dir) or all remotes files/dir if any
of the remote is a file. The path will be stripped, that is only filename,
or dirname will be downloaded into dest dir


```go
func (s *SshExec) FetchUseCLI(dest string, remoteSrc ...string) (out string, err error)
```
Fetch (Download) from remote to local. If remote is a file doesnload the
file. If a dir, download the whole dir. The dest dir is local dir and its
contents are remote dir (if remote is a dir) or all remotes files/dir if any
of the remote is a file. The path will be stripped, that is only filename,
or dirname will be downloaded into dest dir


```go
func (s *SshExec) GoTemplate(src, dest string, data map[string]any, mode os.FileMode) (remoteFilePath string, err error)
```
Take local go template file, template it and copy to remote hosts. If the
src has multilines then treat is as the template string. If dest is empty
string or not absolute path, create a temp dir and template file into it
return the remote templated file path




### Type StreamDecryptReader
```go
type StreamDecryptReader struct {
	// contains filtered or unexported fields
}
```
StreamDecryptReader implements io.ReadCloser

### Methods

```go
func (s *StreamDecryptReader) Close() error
```


```go
func (s *StreamDecryptReader) Read(p []byte) (int, error)
```
Read returns decrypted plaintext, verifying each frame before returning its
bytes.




### Type StreamEncryptOpt
```go
type StreamEncryptOpt func(*StreamEncryptWriter)
```
StreamEncryptOption helpers

### Functions

```go
func WithFrameSize(sz int) StreamEncryptOpt
```


```go
func WithPBKDF2Iter(i uint32) StreamEncryptOpt
```




### Type StreamEncryptWriter
```go
type StreamEncryptWriter struct {
	// contains filtered or unexported fields
}
```
StreamEncryptWriter implements io.WriteCloser

### Functions

```go
func NewStreamEncryptWriter(w io.Writer, password string, opts ...StreamEncryptOpt) (*StreamEncryptWriter, error)
```
NewStreamEncryptWriter writes a header then streams framed ciphertext+tag.
MUST call Close() to flush any final partial frame.



### Methods

```go
func (s *StreamEncryptWriter) Close() error
```
Close flushes final partial frame and attempts to close underlying if it is
a Closer.


```go
func (s *StreamEncryptWriter) Write(p []byte) (int, error)
```
Write buffers up to frameSize; when full it encrypts+tags+writes a frame.
It returns number of bytes consumed from p or an error.




### Type StructInfo
```go
type StructInfo struct {
	// Name of the struct
	Name string
	// List of all struct field names
	FieldName []string
	// map lookup by field name => field type
	FieldType map[string]string
	// map lookup by field name => field value
	FieldValue map[string]any
	// map lookup by field name => the capture of struct tags. When calling ReflectStruct you give it the tagPtn
	// here is what you get by using FindAllStringSubmatch of that regex ptn.
	TagCapture map[string][][]string
}
```
StructInfo hold information about a struct

### Functions

```go
func ReflectStruct(astruct any, tagPtn string) StructInfo
```
Give it a struct and a tag pattern to capture the tag content - return a
StructInfo obj




### Type SystemCommandOuput
```go
type SystemCommandOuput struct {
	Stdout string `json:"Stdout"`
	Stderr string `json:"Stderr"`
	Cmd    string `json:"Cmd"`
}
```
The output of the function RunSystemCommandXXX when there is error. Without
error it just return the raw command output from the shell This allows the
caller to fine parse the error and deal with it


### Type TarOptions
```go
type TarOptions struct {
	UseCompression   bool
	Format           CompressionFormat // NEW: which algorithm to use
	Encrypt          bool
	EncryptMode      EncryptMode
	Password         string
	CompressionLevel int // meaning depends on Format: zstd 1-22, gzip 1-9, xz 0-9
	StripTopLevelDir bool
}
```
TarOptions contains configuration for the tar creation

### Functions

```go
func NewTarOptions() *TarOptions
```



### Methods

```go
func (zo *TarOptions) EnableCompression(enabled bool) *TarOptions
```


```go
func (zo *TarOptions) WithCompressionLevel(level int) *TarOptions
```


```go
func (zo *TarOptions) WithEncrypt(enabled bool) *TarOptions
```


```go
func (zo *TarOptions) WithEncryptMode(m EncryptMode) *TarOptions
```


```go
func (zo *TarOptions) WithFormat(f CompressionFormat) *TarOptions
```


```go
func (zo *TarOptions) WithPassword(pass string) *TarOptions
```


```go
func (zo *TarOptions) WithStripTopLevelDir(s bool) *TarOptions
```




### Type ZipOptions
```go
type ZipOptions struct {
	UseCompression   bool
	CompressionLevel int // 0-9 for ZIP, -1 for default
	// Use GCM only as Zipreader requires fixed block in reader. To handle large file, disable encryption, write to temporary file, then call stream CTR encryption to convert the file at the caller side
	Encrypt  bool
	Password string
}
```
ZipOptions contains configuration for ZIP creation

### Functions

```go
func NewZipOptions() *ZipOptions
```



### Methods

```go
func (zo *ZipOptions) EnableCompression(enabled bool) *ZipOptions
```


```go
func (zo *ZipOptions) WithCompressionLevel(level int) *ZipOptions
```


```go
func (zo *ZipOptions) WithEncrypt(enabled bool) *ZipOptions
```


```go
func (zo *ZipOptions) WithPassword(pass string) *ZipOptions
```






## Examples
### [ExampleSha256SumFile](https://pkg.go.dev/github.com/sunshine69/golang-tools/utils?tab=doc#example-Sha256SumFile)




