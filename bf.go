
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
    n := make([]sync.WaitGroup, 58)

    go func(w []sync.WaitGroup, j *sync.WaitGroup){

        j.Add(1)
    
    }(n[1:3], &n[3])
    go func(w []sync.WaitGroup, j *sync.WaitGroup){

        j.Add(1)
    
    }(n[3:5], &n[1])
    go func(w []sync.WaitGroup, j *sync.WaitGroup){

        j.Add(1)
    
    }(n[5:7], &n[7])
    go func(w []sync.WaitGroup, j *sync.WaitGroup){

        j.Add(1)
    
    }(n[7:9], &n[5])
    go func(w []sync.WaitGroup, j *sync.WaitGroup){

        j.Add(1)
    
    }(n[18:20], &n[31])
    go func(w []sync.WaitGroup, j *sync.WaitGroup){

        j.Add(1)
    
    }(n[31:33], &n[18])
    go func(w []sync.WaitGroup, j *sync.WaitGroup){

        os.Stdout.Write(m)
    }(n[33:35], nil)
    go func(w []sync.WaitGroup, j *sync.WaitGroup){

        j.Add(1)
    
    }(n[39:41], &n[51])
    go func(w []sync.WaitGroup, j *sync.WaitGroup){

        j.Add(1)
    
    }(n[51:53], &n[39])
    go func(w []sync.WaitGroup, j *sync.WaitGroup){

        os.Stdout.Write(m)
    }(n[54:56], nil)
    n[57].Wait()
}
