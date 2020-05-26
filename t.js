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
let code = `
package main

import (
    "bufio"
    "sync"
    "os"
)

func main() {
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
    code += `
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
${pattern[bf[i]]}
            c.Add(1)
        }
    }(&n[${i}], &n[${i+1}], ${brackets[i] ? `&n[${brackets[i]}]` : `nil`})`
}

code += `
    n[0].Done()
    n[${bf.length}].Wait()
    os.Exit(0)
}
`
writeFileSync('bf.go', code)