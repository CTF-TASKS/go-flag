const { writeFileSync } = require('fs')

const brackets = {}
const opened = []
const bf = '>[-]>[-]<>++++++++[-<+++++++++>]<.>++++[-<++++++++>]<+.<'
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
    '>': ``,
    '.': `
        os.Stdout.write()`,
    '[': `
        
    `
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
    w := make([]byte, 1000)
    i := make([]sync.WaitGroup, ${bf.length + 2})
`

for (let i = 0; i < bf.length; i++) {
    code += `
    go func(w []sync.WaitGroup, j *sync.WaitGroup){
${pattern[bf[i]]}
    }(i[${i}:${i+2}], ${brackets[i] ? `&i[${brackets[i]}]` : `nil`})`
}

code += `
}
`
writeFileSync('bf.go', code)