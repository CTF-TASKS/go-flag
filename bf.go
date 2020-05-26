
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
    n := make([]sync.WaitGroup, 57)
    for idx := range n {
        n[idx].Add(1)
    }

    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i++
        w.Done()
            c.Add(1)
        }
    }(&n[0], &n[1], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
            c.Add(1)
        }
    }(&n[1], &n[2], &n[3])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]--
        w.Done()
            c.Add(1)
        }
    }(&n[2], &n[3], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        j.Done()
    
            c.Add(1)
        }
    }(&n[3], &n[4], &n[1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i++
        w.Done()
            c.Add(1)
        }
    }(&n[4], &n[5], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
            c.Add(1)
        }
    }(&n[5], &n[6], &n[7])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]--
        w.Done()
            c.Add(1)
        }
    }(&n[6], &n[7], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        j.Done()
    
            c.Add(1)
        }
    }(&n[7], &n[8], &n[5])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i--
        w.Done()
            c.Add(1)
        }
    }(&n[8], &n[9], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i++
        w.Done()
            c.Add(1)
        }
    }(&n[9], &n[10], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[10], &n[11], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[11], &n[12], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[12], &n[13], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[13], &n[14], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[14], &n[15], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[15], &n[16], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[16], &n[17], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[17], &n[18], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
            c.Add(1)
        }
    }(&n[18], &n[19], &n[31])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]--
        w.Done()
            c.Add(1)
        }
    }(&n[19], &n[20], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i--
        w.Done()
            c.Add(1)
        }
    }(&n[20], &n[21], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[21], &n[22], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[22], &n[23], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[23], &n[24], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[24], &n[25], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[25], &n[26], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[26], &n[27], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[27], &n[28], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[28], &n[29], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[29], &n[30], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i++
        w.Done()
            c.Add(1)
        }
    }(&n[30], &n[31], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        j.Done()
    
            c.Add(1)
        }
    }(&n[31], &n[32], &n[18])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i--
        w.Done()
            c.Add(1)
        }
    }(&n[32], &n[33], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
            c.Add(1)
        }
    }(&n[33], &n[34], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i++
        w.Done()
            c.Add(1)
        }
    }(&n[34], &n[35], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[35], &n[36], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[36], &n[37], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[37], &n[38], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[38], &n[39], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
            c.Add(1)
        }
    }(&n[39], &n[40], &n[51])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]--
        w.Done()
            c.Add(1)
        }
    }(&n[40], &n[41], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i--
        w.Done()
            c.Add(1)
        }
    }(&n[41], &n[42], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[42], &n[43], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[43], &n[44], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[44], &n[45], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[45], &n[46], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[46], &n[47], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[47], &n[48], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[48], &n[49], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[49], &n[50], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i++
        w.Done()
            c.Add(1)
        }
    }(&n[50], &n[51], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        j.Done()
    
            c.Add(1)
        }
    }(&n[51], &n[52], &n[39])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i--
        w.Done()
            c.Add(1)
        }
    }(&n[52], &n[53], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        m[i]++
        w.Done()
            c.Add(1)
        }
    }(&n[53], &n[54], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
            c.Add(1)
        }
    }(&n[54], &n[55], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()

        i--
        w.Done()
            c.Add(1)
        }
    }(&n[55], &n[56], nil)
    n[0].Done()
    n[56].Wait()
    os.Exit(0)
}
