package match

import (
    "fmt"
    "github.com/armon/go-radix"
    "math/rand"
    "strings"
    "bufio"
    "os"
    //"time"
)

/*func main() {

    domain_list := LoadDomainList("../DP/data/sld-Alexa-top-1m.txt", -1)

    fmt.Println(domain_list)

    start := time.Now()

    domain_radix := SuffixMatchCreateRadix(domain_list, ".")

    fmt.Println(time.Since(start))

    start = time.Now()

    domain_map := ExactMatchCreateMap(domain_list)

    fmt.Println(time.Since(start))

    for i := 0; i < 20; i++ {

        entry := get_random_load_entry(domain_list)

        fmt.Println("entry", entry)

        fmt.Println("exact match", ExactMatch(domain_map, entry))

        fmt.Println("suffix match", SuffixMatch(domain_radix, entry, "."))

        nonentry := get_random_load_nonentry(domain_list)

        fmt.Println("nonentry ", nonentry)

        fmt.Println("exact match", ExactMatch(domain_map, nonentry))

        fmt.Println("suffix match", SuffixMatch(domain_radix, nonentry, "."))
    }
}*/

//Input: File Path
//Output: List of domains, No.of domains (-1 represents full list)
//Function: Load domains from file to list
func LoadDomainList(file_path string, no_of_domains int) (domain_list []string) {

    if no_of_domains < -1 {//If no. of domains negative

        checkError(fmt.Errorf("Invalid no. of domains")) //Invalid no. of domains    
    }

    count := 0 //Count of domains

    //Open file
    file, err := os.Open(file_path)
    checkError(err)
    defer file.Close()

    //Read line by line
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {

        count = count + 1 //Increment count

        if no_of_domains != -1 { //If not entire list

            if count > no_of_domains { //If count exceeds no. of domains

                break
            }
        }

        domain := strings.ToLower(scanner.Text()) //Convert to lower case
        domain = strings.Trim(domain, " ") //Strip white spaces
        domain_list = append(domain_list, domain) //Create a list of domains
    }

    checkError(scanner.Err()) //Check for scanner error

    return domain_list
}

//Input: List of domains
//Output: Map of domains
//Function: Create a map of domains
func ExactMatchCreateMap(domain_list []string) (map[string]bool) {

    m := map[string]bool{} //Map

    for _, domains := range domain_list { //Iterate over domains

        if m[strings.ToLower(domains)] == false { //Convert to lower case and check if not duplicate

            m[strings.ToLower(domains)] = true //Add domain to map
        }
    }

    return m
}

//Input: Exact match map, Search string
//Output: Has an exact match or not
//Function: Returns true on match and false on no match
func ExactMatch(match_map map[string]bool, search_string string) (exact_match string) {

    exact_match = strings.ToLower(search_string) //Convert to lower case

    if match_map[exact_match] == false { //If not in map

        exact_match = "" //No match
    }

    return exact_match
}

//Input: Suffix string, Separator
//Output: Reversed suffix
//Function: Convert to lowercase and return a reversed list of suffix components separated by separator
func SuffixMatchReverse(suffix string, sep string) (suffix_rev string) {

    suffix = strings.ToLower(suffix) //Convert to lower case

    suffix = strings.Trim(suffix, sep) //Strip separator off

    comp := strings.Split(suffix, sep) //Split suffix to components

    comp_rev := make([]string, len(comp)) //Reverse component list

    for i := 0; i < len(comp); i++ { //Iterate over components

        comp_rev[len(comp)-i-1] = comp[i] //Reverse list
    }

    suffix_rev = strings.Join(comp_rev, sep) //Reversed suffix

    return suffix_rev
}

//Input: List of domains, Separator
//Output: Radix tree of domains
//Function: Create a radix tree of domains
func SuffixMatchCreateRadix(domain_list []string, sep string) (*radix.Tree) {

    r := radix.New() //Radix tree

    for _, domains := range domain_list { //Iterate over domains

        domain_rev := SuffixMatchReverse(domains, sep) //Reversed domain

        lp, _, _ := r.LongestPrefix(domain_rev) //Find longest prefix

        if lp == "" || !(strings.HasPrefix(domain_rev, lp + sep)) { //If no longest pre-fix exists

            r.Insert(domain_rev, "{}") //Insert domain into radix

            r.DeletePrefix(domain_rev + sep)
        }
    }

    return r
}

//Input: Suffix radix tree, Search string, Separator
//Output: Has a suffix match or not
//Function: Returns true on match and false on no match
func SuffixMatch(suffix_radix *radix.Tree, search_string string, sep string) (suffix_match string) {

    search_string_rev := SuffixMatchReverse(search_string, sep) //Reversed search string

    lp, _, _ := suffix_radix.LongestPrefix(search_string_rev) //Find longest prefix

    if lp == "" { //If longest prefix does not exist

        suffix_match = "" //No suffix match

    } else { //If longest prefix exists

        suffix_match = SuffixMatchReverse(lp, sep) //Suffix match is the reversed longest prefix
    }

    return suffix_match
}

//Input: List of domains
//Output: Random domain
//Function: Choose a random domain from list of domains
func get_random_load_entry(domain_list []string) string {

    return domain_list[rand.Int31n(int32(len(domain_list)))]
}

//Input: List of domains
//Output: Random non-entry
//Function: Return a random entry not in list of domains
func get_random_load_nonentry(domain_list []string) string {

    entry := get_random_load_entry(domain_list)

    perm := rand.Perm(len(entry))

    nonentry := ""

    for _, i := range perm {

        nonentry = nonentry + string(entry[i])
    }

    return nonentry
}

//Input: Error
//Function: Check Error
func checkError(err error) {
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
