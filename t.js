const { writeFileSync, readFileSync } = require('fs')
const { execSync } = require('child_process')

const FLAG = 'RCTF{my_br4in_is_f__ked}'
const code = `
bool check_flag() {
    bool r = true;
${FLAG.split('').map(i => `    if ('${i}' != readchar()) { r = false; }`).join('\n')}
    return r;
}

int main() {
    print("Please input the flag:\\n");
    if (check_flag()) {
        print("Correct!\\n");
    } else {
        print("Wrong!\\n");
    }
}
`

writeFileSync('src.code', code)

execSync("python3 BF-it/BF-it.py src.code -o src.bf")

const brackets = {}
const opened = []
const bf = readFileSync('src.bf', 'utf-8').trim()
for (let i = 0; i < bf.length; i++) {
    if (bf[i] === '[') {
        opened.push(i)
    } else if (bf[i] === ']') {
        const opening = opened.pop()
        brackets[opening] = i
        brackets[i] = opening
    }
}
const pattern = {
    '+': `
        m[i]++
        w.Done()`,
    '-': `
        m[i]--
        w.Done()`,
    '<': `
        i--
        w.Done()`,
    '>': `
        i++
        w.Done()`,
    '.': `
        io.WriteByte(m[i])
        io.Flush()
        w.Done()`,
    ',': `
        m[i] = <- in
        w.Done()`,
    '[': `
        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    `,
    ']': `
        j.Done()
    `,
}
let goCode = `
package main

import (
    "bufio"
    "io"
    "sync"
    "os"
)

func main() {
    in := make(chan byte, 1)
    go func() {
        data := make([]byte, 1)
        var err error
        var n int
        for err != io.EOF {
            n, err = os.Stdin.Read(data)
            if n > 0 {
                in <- data[0]
            }
        }
    }()
	io := bufio.NewReadWriter(bufio.NewReader(os.Stdin), bufio.NewWriter(os.Stdout))
    m := make([]byte, 1000)
    i := 0
    n := make([]sync.WaitGroup, ${bf.length + 1})
    for idx := range n {
        n[idx].Add(1)
    }
`

for (let i = 0; i < bf.length; i++) {
    if (!pattern[bf[i]]) continue
    goCode += `
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)
${pattern[bf[i]]}
        }
    }(&n[${i}], &n[${i+1}], ${brackets[i] ? `&n[${brackets[i]} + ${bf[i] === '[' ? 1 : 0}]` : `nil`})`
}

goCode += `
    n[0].Done()
    n[${bf.length}].Wait()
    os.Exit(0)
}
`
writeFileSync('bf.go', goCode)
