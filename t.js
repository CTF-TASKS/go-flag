const { writeFileSync, readFileSync } = require('fs')

const brackets = {}
const opened = []
const bf = readFileSync('src.bf', 'utf-8')
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
    '+': ``,
    '-': ``,
    '<': ``,
    '>': ``,
    '.': `
        os.Stdout.Write(m)`,
    '[': `
        j.Add(1)
    `,
    ']': `
        j.Add(1)
    `,
}
let code = `
package main

import (
    "bufio"
    "sync"
    "os"
)

func main() {
    reader := bufio.NewReader(os.Stdin)
    m := make([]byte, 1000)
    i := 0
    n := make([]sync.WaitGroup, ${bf.length + 2})
`

for (let i = 0; i < bf.length; i++) {
    if (!pattern[bf[i]]) continue
    code += `
    go func(w []sync.WaitGroup, j *sync.WaitGroup){
${pattern[bf[i]]}
    }(n[${i}:${i+2}], ${brackets[i] ? `&n[${brackets[i]}]` : `nil`})`
}

code += `
    n[${bf.length + 1}].Wait()
}
`
writeFileSync('bf.go', code)