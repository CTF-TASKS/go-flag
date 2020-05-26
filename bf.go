
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
    n := make([]sync.WaitGroup, 3136)
    for idx := range n {
        n[idx].Add(1)
    }

    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[0], &n[1], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1], &n[2], &n[3 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2], &n[3], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[3], &n[4], &n[1 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[4], &n[5], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[5], &n[6], &n[7 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[6], &n[7], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[7], &n[8], &n[5 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[8], &n[9], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[9], &n[10], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[10], &n[11], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[11], &n[12], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[12], &n[13], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[13], &n[14], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[14], &n[15], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[15], &n[16], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[16], &n[17], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[17], &n[18], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[18], &n[19], &n[32 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[19], &n[20], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[20], &n[21], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[21], &n[22], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[22], &n[23], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[23], &n[24], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[24], &n[25], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[25], &n[26], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[26], &n[27], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[27], &n[28], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[28], &n[29], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[29], &n[30], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[30], &n[31], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[31], &n[32], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[32], &n[33], &n[18 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[33], &n[34], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[34], &n[35], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[35], &n[36], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[36], &n[37], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[37], &n[38], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[38], &n[39], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[39], &n[40], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[40], &n[41], &n[51 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[41], &n[42], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[42], &n[43], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[43], &n[44], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[44], &n[45], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[45], &n[46], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[46], &n[47], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[47], &n[48], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[48], &n[49], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[49], &n[50], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[50], &n[51], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[51], &n[52], &n[40 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[52], &n[53], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[53], &n[54], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[54], &n[55], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[55], &n[56], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[56], &n[57], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[57], &n[58], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[58], &n[59], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[59], &n[60], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[60], &n[61], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[61], &n[62], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[62], &n[63], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[63], &n[64], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[64], &n[65], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[65], &n[66], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[66], &n[67], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[67], &n[68], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[68], &n[69], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[69], &n[70], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[70], &n[71], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[71], &n[72], &n[81 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[72], &n[73], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[73], &n[74], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[74], &n[75], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[75], &n[76], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[76], &n[77], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[77], &n[78], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[78], &n[79], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[79], &n[80], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[80], &n[81], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[81], &n[82], &n[71 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[82], &n[83], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[83], &n[84], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[84], &n[85], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[85], &n[86], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[86], &n[87], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[87], &n[88], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[88], &n[89], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[89], &n[90], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[90], &n[91], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[91], &n[92], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[92], &n[93], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[93], &n[94], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[94], &n[95], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[95], &n[96], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[96], &n[97], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[97], &n[98], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[98], &n[99], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[99], &n[100], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[100], &n[101], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[101], &n[102], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[102], &n[103], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[103], &n[104], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[104], &n[105], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[105], &n[106], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[106], &n[107], &n[121 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[107], &n[108], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[108], &n[109], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[109], &n[110], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[110], &n[111], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[111], &n[112], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[112], &n[113], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[113], &n[114], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[114], &n[115], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[115], &n[116], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[116], &n[117], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[117], &n[118], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[118], &n[119], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[119], &n[120], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[120], &n[121], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[121], &n[122], &n[106 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[122], &n[123], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[123], &n[124], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[124], &n[125], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[125], &n[126], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[126], &n[127], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[127], &n[128], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[128], &n[129], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[129], &n[130], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[130], &n[131], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[131], &n[132], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[132], &n[133], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[133], &n[134], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[134], &n[135], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[135], &n[136], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[136], &n[137], &n[149 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[137], &n[138], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[138], &n[139], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[139], &n[140], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[140], &n[141], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[141], &n[142], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[142], &n[143], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[143], &n[144], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[144], &n[145], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[145], &n[146], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[146], &n[147], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[147], &n[148], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[148], &n[149], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[149], &n[150], &n[136 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[150], &n[151], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[151], &n[152], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[152], &n[153], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[153], &n[154], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[154], &n[155], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[155], &n[156], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[156], &n[157], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[157], &n[158], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[158], &n[159], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[159], &n[160], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[160], &n[161], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[161], &n[162], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[162], &n[163], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[163], &n[164], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[164], &n[165], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[165], &n[166], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[166], &n[167], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[167], &n[168], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[168], &n[169], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[169], &n[170], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[170], &n[171], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[171], &n[172], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[172], &n[173], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[173], &n[174], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[174], &n[175], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[175], &n[176], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[176], &n[177], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[177], &n[178], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[178], &n[179], &n[194 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[179], &n[180], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[180], &n[181], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[181], &n[182], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[182], &n[183], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[183], &n[184], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[184], &n[185], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[185], &n[186], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[186], &n[187], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[187], &n[188], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[188], &n[189], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[189], &n[190], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[190], &n[191], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[191], &n[192], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[192], &n[193], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[193], &n[194], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[194], &n[195], &n[178 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[195], &n[196], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[196], &n[197], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[197], &n[198], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[198], &n[199], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[199], &n[200], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[200], &n[201], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[201], &n[202], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[202], &n[203], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[203], &n[204], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[204], &n[205], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[205], &n[206], &n[221 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[206], &n[207], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[207], &n[208], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[208], &n[209], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[209], &n[210], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[210], &n[211], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[211], &n[212], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[212], &n[213], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[213], &n[214], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[214], &n[215], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[215], &n[216], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[216], &n[217], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[217], &n[218], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[218], &n[219], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[219], &n[220], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[220], &n[221], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[221], &n[222], &n[205 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[222], &n[223], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[223], &n[224], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[224], &n[225], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[225], &n[226], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[226], &n[227], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[227], &n[228], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[228], &n[229], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[229], &n[230], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[230], &n[231], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[231], &n[232], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[232], &n[233], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[233], &n[234], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[234], &n[235], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[235], &n[236], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[236], &n[237], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[237], &n[238], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[238], &n[239], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[239], &n[240], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[240], &n[241], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[241], &n[242], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[242], &n[243], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[243], &n[244], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[244], &n[245], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[245], &n[246], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[246], &n[247], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[247], &n[248], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[248], &n[249], &n[263 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[249], &n[250], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[250], &n[251], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[251], &n[252], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[252], &n[253], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[253], &n[254], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[254], &n[255], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[255], &n[256], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[256], &n[257], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[257], &n[258], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[258], &n[259], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[259], &n[260], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[260], &n[261], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[261], &n[262], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[262], &n[263], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[263], &n[264], &n[248 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[264], &n[265], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[265], &n[266], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[266], &n[267], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[267], &n[268], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[268], &n[269], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[269], &n[270], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[270], &n[271], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[271], &n[272], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[272], &n[273], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[273], &n[274], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[274], &n[275], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[275], &n[276], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[276], &n[277], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[277], &n[278], &n[291 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[278], &n[279], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[279], &n[280], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[280], &n[281], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[281], &n[282], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[282], &n[283], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[283], &n[284], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[284], &n[285], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[285], &n[286], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[286], &n[287], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[287], &n[288], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[288], &n[289], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[289], &n[290], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[290], &n[291], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[291], &n[292], &n[277 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[292], &n[293], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[293], &n[294], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[294], &n[295], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[295], &n[296], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[296], &n[297], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[297], &n[298], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[298], &n[299], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[299], &n[300], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[300], &n[301], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[301], &n[302], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[302], &n[303], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[303], &n[304], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[304], &n[305], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[305], &n[306], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[306], &n[307], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[307], &n[308], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[308], &n[309], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[309], &n[310], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[310], &n[311], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[311], &n[312], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[312], &n[313], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[313], &n[314], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[314], &n[315], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[315], &n[316], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[316], &n[317], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[317], &n[318], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[318], &n[319], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[319], &n[320], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[320], &n[321], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[321], &n[322], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[322], &n[323], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[323], &n[324], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[324], &n[325], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[325], &n[326], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[326], &n[327], &n[339 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[327], &n[328], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[328], &n[329], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[329], &n[330], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[330], &n[331], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[331], &n[332], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[332], &n[333], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[333], &n[334], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[334], &n[335], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[335], &n[336], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[336], &n[337], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[337], &n[338], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[338], &n[339], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[339], &n[340], &n[326 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[340], &n[341], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[341], &n[342], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[342], &n[343], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[343], &n[344], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[344], &n[345], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[345], &n[346], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[346], &n[347], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[347], &n[348], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[348], &n[349], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[349], &n[350], &n[361 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[350], &n[351], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[351], &n[352], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[352], &n[353], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[353], &n[354], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[354], &n[355], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[355], &n[356], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[356], &n[357], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[357], &n[358], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[358], &n[359], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[359], &n[360], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[360], &n[361], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[361], &n[362], &n[349 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[362], &n[363], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[363], &n[364], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[364], &n[365], &n[366 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[365], &n[366], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[366], &n[367], &n[364 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[367], &n[368], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[368], &n[369], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[369], &n[370], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[370], &n[371], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[371], &n[372], &n[373 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[372], &n[373], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[373], &n[374], &n[371 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[374], &n[375], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[375], &n[376], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[376], &n[377], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[377], &n[378], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[378], &n[379], &n[380 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[379], &n[380], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[380], &n[381], &n[378 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[381], &n[382], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[382], &n[383], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[383], &n[384], &n[385 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[384], &n[385], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[385], &n[386], &n[383 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[386], &n[387], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[387], &n[388], &n[395 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[388], &n[389], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[389], &n[390], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[390], &n[391], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[391], &n[392], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[392], &n[393], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[393], &n[394], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[394], &n[395], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[395], &n[396], &n[387 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[396], &n[397], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[397], &n[398], &n[402 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[398], &n[399], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[399], &n[400], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[400], &n[401], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[401], &n[402], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[402], &n[403], &n[397 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[403], &n[404], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[404], &n[405], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[405], &n[406], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[406], &n[407], &n[408 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[407], &n[408], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[408], &n[409], &n[406 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[409], &n[410], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[410], &n[411], &n[412 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[411], &n[412], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[412], &n[413], &n[410 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[413], &n[414], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[414], &n[415], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[415], &n[416], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[416], &n[417], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[417], &n[418], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[418], &n[419], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[419], &n[420], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[420], &n[421], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[421], &n[422], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[422], &n[423], &n[435 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[423], &n[424], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[424], &n[425], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[425], &n[426], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[426], &n[427], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[427], &n[428], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[428], &n[429], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[429], &n[430], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[430], &n[431], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[431], &n[432], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[432], &n[433], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[433], &n[434], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[434], &n[435], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[435], &n[436], &n[422 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[436], &n[437], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[437], &n[438], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[438], &n[439], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[439], &n[440], &n[441 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[440], &n[441], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[441], &n[442], &n[439 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[442], &n[443], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[443], &n[444], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[444], &n[445], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[445], &n[446], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[446], &n[447], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[447], &n[448], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[448], &n[449], &n[453 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[449], &n[450], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[450], &n[451], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[451], &n[452], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[452], &n[453], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[453], &n[454], &n[448 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[454], &n[455], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[455], &n[456], &n[462 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[456], &n[457], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[457], &n[458], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[458], &n[459], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[459], &n[460], &n[461 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[460], &n[461], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[461], &n[462], &n[459 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[462], &n[463], &n[455 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[463], &n[464], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[464], &n[465], &n[502 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[465], &n[466], &n[467 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[466], &n[467], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[467], &n[468], &n[465 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[468], &n[469], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[469], &n[470], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[470], &n[471], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[471], &n[472], &n[473 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[472], &n[473], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[473], &n[474], &n[471 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[474], &n[475], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[475], &n[476], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[476], &n[477], &n[478 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[477], &n[478], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[478], &n[479], &n[476 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[479], &n[480], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[480], &n[481], &n[488 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[481], &n[482], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[482], &n[483], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[483], &n[484], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[484], &n[485], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[485], &n[486], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[486], &n[487], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[487], &n[488], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[488], &n[489], &n[480 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[489], &n[490], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[490], &n[491], &n[495 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[491], &n[492], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[492], &n[493], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[493], &n[494], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[494], &n[495], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[495], &n[496], &n[490 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[496], &n[497], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[497], &n[498], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[498], &n[499], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[499], &n[500], &n[501 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[500], &n[501], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[501], &n[502], &n[499 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[502], &n[503], &n[464 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[503], &n[504], &n[505 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[504], &n[505], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[505], &n[506], &n[503 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[506], &n[507], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[507], &n[508], &n[509 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[508], &n[509], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[509], &n[510], &n[507 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[510], &n[511], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[511], &n[512], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[512], &n[513], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[513], &n[514], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[514], &n[515], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[515], &n[516], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[516], &n[517], &n[531 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[517], &n[518], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[518], &n[519], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[519], &n[520], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[520], &n[521], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[521], &n[522], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[522], &n[523], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[523], &n[524], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[524], &n[525], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[525], &n[526], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[526], &n[527], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[527], &n[528], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[528], &n[529], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[529], &n[530], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[530], &n[531], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[531], &n[532], &n[516 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[532], &n[533], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[533], &n[534], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[534], &n[535], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[535], &n[536], &n[537 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[536], &n[537], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[537], &n[538], &n[535 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[538], &n[539], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[539], &n[540], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[540], &n[541], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[541], &n[542], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[542], &n[543], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[543], &n[544], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[544], &n[545], &n[549 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[545], &n[546], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[546], &n[547], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[547], &n[548], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[548], &n[549], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[549], &n[550], &n[544 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[550], &n[551], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[551], &n[552], &n[558 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[552], &n[553], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[553], &n[554], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[554], &n[555], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[555], &n[556], &n[557 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[556], &n[557], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[557], &n[558], &n[555 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[558], &n[559], &n[551 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[559], &n[560], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[560], &n[561], &n[598 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[561], &n[562], &n[563 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[562], &n[563], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[563], &n[564], &n[561 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[564], &n[565], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[565], &n[566], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[566], &n[567], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[567], &n[568], &n[569 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[568], &n[569], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[569], &n[570], &n[567 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[570], &n[571], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[571], &n[572], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[572], &n[573], &n[574 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[573], &n[574], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[574], &n[575], &n[572 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[575], &n[576], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[576], &n[577], &n[584 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[577], &n[578], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[578], &n[579], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[579], &n[580], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[580], &n[581], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[581], &n[582], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[582], &n[583], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[583], &n[584], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[584], &n[585], &n[576 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[585], &n[586], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[586], &n[587], &n[591 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[587], &n[588], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[588], &n[589], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[589], &n[590], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[590], &n[591], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[591], &n[592], &n[586 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[592], &n[593], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[593], &n[594], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[594], &n[595], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[595], &n[596], &n[597 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[596], &n[597], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[597], &n[598], &n[595 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[598], &n[599], &n[560 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[599], &n[600], &n[601 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[600], &n[601], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[601], &n[602], &n[599 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[602], &n[603], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[603], &n[604], &n[605 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[604], &n[605], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[605], &n[606], &n[603 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[606], &n[607], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[607], &n[608], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[608], &n[609], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[609], &n[610], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[610], &n[611], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[611], &n[612], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[612], &n[613], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[613], &n[614], &n[629 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[614], &n[615], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[615], &n[616], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[616], &n[617], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[617], &n[618], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[618], &n[619], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[619], &n[620], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[620], &n[621], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[621], &n[622], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[622], &n[623], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[623], &n[624], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[624], &n[625], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[625], &n[626], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[626], &n[627], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[627], &n[628], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[628], &n[629], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[629], &n[630], &n[613 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[630], &n[631], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[631], &n[632], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[632], &n[633], &n[634 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[633], &n[634], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[634], &n[635], &n[632 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[635], &n[636], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[636], &n[637], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[637], &n[638], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[638], &n[639], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[639], &n[640], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[640], &n[641], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[641], &n[642], &n[646 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[642], &n[643], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[643], &n[644], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[644], &n[645], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[645], &n[646], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[646], &n[647], &n[641 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[647], &n[648], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[648], &n[649], &n[655 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[649], &n[650], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[650], &n[651], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[651], &n[652], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[652], &n[653], &n[654 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[653], &n[654], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[654], &n[655], &n[652 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[655], &n[656], &n[648 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[656], &n[657], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[657], &n[658], &n[695 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[658], &n[659], &n[660 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[659], &n[660], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[660], &n[661], &n[658 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[661], &n[662], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[662], &n[663], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[663], &n[664], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[664], &n[665], &n[666 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[665], &n[666], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[666], &n[667], &n[664 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[667], &n[668], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[668], &n[669], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[669], &n[670], &n[671 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[670], &n[671], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[671], &n[672], &n[669 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[672], &n[673], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[673], &n[674], &n[681 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[674], &n[675], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[675], &n[676], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[676], &n[677], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[677], &n[678], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[678], &n[679], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[679], &n[680], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[680], &n[681], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[681], &n[682], &n[673 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[682], &n[683], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[683], &n[684], &n[688 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[684], &n[685], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[685], &n[686], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[686], &n[687], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[687], &n[688], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[688], &n[689], &n[683 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[689], &n[690], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[690], &n[691], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[691], &n[692], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[692], &n[693], &n[694 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[693], &n[694], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[694], &n[695], &n[692 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[695], &n[696], &n[657 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[696], &n[697], &n[698 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[697], &n[698], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[698], &n[699], &n[696 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[699], &n[700], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[700], &n[701], &n[702 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[701], &n[702], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[702], &n[703], &n[700 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[703], &n[704], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[704], &n[705], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[705], &n[706], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[706], &n[707], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[707], &n[708], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[708], &n[709], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[709], &n[710], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[710], &n[711], &n[724 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[711], &n[712], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[712], &n[713], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[713], &n[714], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[714], &n[715], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[715], &n[716], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[716], &n[717], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[717], &n[718], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[718], &n[719], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[719], &n[720], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[720], &n[721], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[721], &n[722], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[722], &n[723], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[723], &n[724], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[724], &n[725], &n[710 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[725], &n[726], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[726], &n[727], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[727], &n[728], &n[729 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[728], &n[729], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[729], &n[730], &n[727 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[730], &n[731], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[731], &n[732], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[732], &n[733], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[733], &n[734], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[734], &n[735], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[735], &n[736], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[736], &n[737], &n[741 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[737], &n[738], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[738], &n[739], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[739], &n[740], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[740], &n[741], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[741], &n[742], &n[736 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[742], &n[743], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[743], &n[744], &n[750 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[744], &n[745], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[745], &n[746], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[746], &n[747], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[747], &n[748], &n[749 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[748], &n[749], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[749], &n[750], &n[747 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[750], &n[751], &n[743 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[751], &n[752], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[752], &n[753], &n[790 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[753], &n[754], &n[755 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[754], &n[755], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[755], &n[756], &n[753 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[756], &n[757], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[757], &n[758], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[758], &n[759], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[759], &n[760], &n[761 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[760], &n[761], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[761], &n[762], &n[759 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[762], &n[763], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[763], &n[764], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[764], &n[765], &n[766 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[765], &n[766], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[766], &n[767], &n[764 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[767], &n[768], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[768], &n[769], &n[776 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[769], &n[770], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[770], &n[771], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[771], &n[772], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[772], &n[773], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[773], &n[774], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[774], &n[775], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[775], &n[776], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[776], &n[777], &n[768 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[777], &n[778], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[778], &n[779], &n[783 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[779], &n[780], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[780], &n[781], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[781], &n[782], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[782], &n[783], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[783], &n[784], &n[778 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[784], &n[785], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[785], &n[786], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[786], &n[787], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[787], &n[788], &n[789 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[788], &n[789], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[789], &n[790], &n[787 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[790], &n[791], &n[752 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[791], &n[792], &n[793 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[792], &n[793], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[793], &n[794], &n[791 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[794], &n[795], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[795], &n[796], &n[797 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[796], &n[797], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[797], &n[798], &n[795 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[798], &n[799], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[799], &n[800], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[800], &n[801], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[801], &n[802], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[802], &n[803], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[803], &n[804], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[804], &n[805], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[805], &n[806], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[806], &n[807], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[807], &n[808], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[808], &n[809], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[809], &n[810], &n[824 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[810], &n[811], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[811], &n[812], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[812], &n[813], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[813], &n[814], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[814], &n[815], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[815], &n[816], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[816], &n[817], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[817], &n[818], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[818], &n[819], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[819], &n[820], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[820], &n[821], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[821], &n[822], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[822], &n[823], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[823], &n[824], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[824], &n[825], &n[809 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[825], &n[826], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[826], &n[827], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[827], &n[828], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[828], &n[829], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[829], &n[830], &n[831 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[830], &n[831], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[831], &n[832], &n[829 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[832], &n[833], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[833], &n[834], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[834], &n[835], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[835], &n[836], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[836], &n[837], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[837], &n[838], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[838], &n[839], &n[843 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[839], &n[840], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[840], &n[841], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[841], &n[842], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[842], &n[843], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[843], &n[844], &n[838 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[844], &n[845], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[845], &n[846], &n[852 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[846], &n[847], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[847], &n[848], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[848], &n[849], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[849], &n[850], &n[851 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[850], &n[851], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[851], &n[852], &n[849 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[852], &n[853], &n[845 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[853], &n[854], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[854], &n[855], &n[892 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[855], &n[856], &n[857 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[856], &n[857], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[857], &n[858], &n[855 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[858], &n[859], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[859], &n[860], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[860], &n[861], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[861], &n[862], &n[863 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[862], &n[863], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[863], &n[864], &n[861 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[864], &n[865], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[865], &n[866], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[866], &n[867], &n[868 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[867], &n[868], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[868], &n[869], &n[866 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[869], &n[870], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[870], &n[871], &n[878 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[871], &n[872], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[872], &n[873], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[873], &n[874], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[874], &n[875], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[875], &n[876], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[876], &n[877], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[877], &n[878], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[878], &n[879], &n[870 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[879], &n[880], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[880], &n[881], &n[885 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[881], &n[882], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[882], &n[883], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[883], &n[884], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[884], &n[885], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[885], &n[886], &n[880 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[886], &n[887], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[887], &n[888], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[888], &n[889], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[889], &n[890], &n[891 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[890], &n[891], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[891], &n[892], &n[889 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[892], &n[893], &n[854 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[893], &n[894], &n[895 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[894], &n[895], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[895], &n[896], &n[893 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[896], &n[897], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[897], &n[898], &n[899 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[898], &n[899], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[899], &n[900], &n[897 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[900], &n[901], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[901], &n[902], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[902], &n[903], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[903], &n[904], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[904], &n[905], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[905], &n[906], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[906], &n[907], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[907], &n[908], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[908], &n[909], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[909], &n[910], &n[925 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[910], &n[911], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[911], &n[912], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[912], &n[913], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[913], &n[914], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[914], &n[915], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[915], &n[916], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[916], &n[917], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[917], &n[918], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[918], &n[919], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[919], &n[920], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[920], &n[921], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[921], &n[922], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[922], &n[923], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[923], &n[924], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[924], &n[925], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[925], &n[926], &n[909 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[926], &n[927], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[927], &n[928], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[928], &n[929], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[929], &n[930], &n[931 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[930], &n[931], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[931], &n[932], &n[929 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[932], &n[933], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[933], &n[934], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[934], &n[935], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[935], &n[936], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[936], &n[937], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[937], &n[938], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[938], &n[939], &n[943 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[939], &n[940], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[940], &n[941], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[941], &n[942], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[942], &n[943], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[943], &n[944], &n[938 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[944], &n[945], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[945], &n[946], &n[952 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[946], &n[947], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[947], &n[948], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[948], &n[949], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[949], &n[950], &n[951 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[950], &n[951], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[951], &n[952], &n[949 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[952], &n[953], &n[945 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[953], &n[954], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[954], &n[955], &n[992 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[955], &n[956], &n[957 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[956], &n[957], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[957], &n[958], &n[955 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[958], &n[959], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[959], &n[960], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[960], &n[961], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[961], &n[962], &n[963 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[962], &n[963], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[963], &n[964], &n[961 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[964], &n[965], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[965], &n[966], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[966], &n[967], &n[968 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[967], &n[968], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[968], &n[969], &n[966 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[969], &n[970], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[970], &n[971], &n[978 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[971], &n[972], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[972], &n[973], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[973], &n[974], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[974], &n[975], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[975], &n[976], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[976], &n[977], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[977], &n[978], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[978], &n[979], &n[970 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[979], &n[980], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[980], &n[981], &n[985 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[981], &n[982], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[982], &n[983], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[983], &n[984], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[984], &n[985], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[985], &n[986], &n[980 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[986], &n[987], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[987], &n[988], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[988], &n[989], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[989], &n[990], &n[991 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[990], &n[991], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[991], &n[992], &n[989 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[992], &n[993], &n[954 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[993], &n[994], &n[995 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[994], &n[995], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[995], &n[996], &n[993 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[996], &n[997], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[997], &n[998], &n[999 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[998], &n[999], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[999], &n[1000], &n[997 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1000], &n[1001], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1001], &n[1002], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1002], &n[1003], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1003], &n[1004], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1004], &n[1005], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1005], &n[1006], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1006], &n[1007], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1007], &n[1008], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1008], &n[1009], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1009], &n[1010], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1010], &n[1011], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1011], &n[1012], &n[1026 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1012], &n[1013], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1013], &n[1014], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1014], &n[1015], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1015], &n[1016], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1016], &n[1017], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1017], &n[1018], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1018], &n[1019], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1019], &n[1020], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1020], &n[1021], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1021], &n[1022], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1022], &n[1023], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1023], &n[1024], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1024], &n[1025], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1025], &n[1026], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1026], &n[1027], &n[1011 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1027], &n[1028], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1028], &n[1029], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1029], &n[1030], &n[1031 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1030], &n[1031], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1031], &n[1032], &n[1029 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1032], &n[1033], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1033], &n[1034], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[1034], &n[1035], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1035], &n[1036], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1036], &n[1037], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1037], &n[1038], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1038], &n[1039], &n[1043 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1039], &n[1040], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1040], &n[1041], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1041], &n[1042], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1042], &n[1043], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1043], &n[1044], &n[1038 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1044], &n[1045], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1045], &n[1046], &n[1052 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1046], &n[1047], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1047], &n[1048], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1048], &n[1049], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1049], &n[1050], &n[1051 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1050], &n[1051], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1051], &n[1052], &n[1049 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1052], &n[1053], &n[1045 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1053], &n[1054], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1054], &n[1055], &n[1092 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1055], &n[1056], &n[1057 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1056], &n[1057], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1057], &n[1058], &n[1055 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1058], &n[1059], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1059], &n[1060], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1060], &n[1061], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1061], &n[1062], &n[1063 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1062], &n[1063], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1063], &n[1064], &n[1061 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1064], &n[1065], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1065], &n[1066], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1066], &n[1067], &n[1068 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1067], &n[1068], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1068], &n[1069], &n[1066 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1069], &n[1070], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1070], &n[1071], &n[1078 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1071], &n[1072], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1072], &n[1073], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1073], &n[1074], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1074], &n[1075], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1075], &n[1076], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1076], &n[1077], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1077], &n[1078], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1078], &n[1079], &n[1070 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1079], &n[1080], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1080], &n[1081], &n[1085 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1081], &n[1082], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1082], &n[1083], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1083], &n[1084], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1084], &n[1085], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1085], &n[1086], &n[1080 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1086], &n[1087], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1087], &n[1088], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1088], &n[1089], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1089], &n[1090], &n[1091 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1090], &n[1091], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1091], &n[1092], &n[1089 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1092], &n[1093], &n[1054 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1093], &n[1094], &n[1095 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1094], &n[1095], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1095], &n[1096], &n[1093 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1096], &n[1097], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1097], &n[1098], &n[1099 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1098], &n[1099], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1099], &n[1100], &n[1097 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1100], &n[1101], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1101], &n[1102], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1102], &n[1103], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1103], &n[1104], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1104], &n[1105], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1105], &n[1106], &n[1128 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1106], &n[1107], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1107], &n[1108], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1108], &n[1109], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1109], &n[1110], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1110], &n[1111], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1111], &n[1112], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1112], &n[1113], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1113], &n[1114], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1114], &n[1115], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1115], &n[1116], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1116], &n[1117], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1117], &n[1118], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1118], &n[1119], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1119], &n[1120], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1120], &n[1121], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1121], &n[1122], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1122], &n[1123], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1123], &n[1124], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1124], &n[1125], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1125], &n[1126], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1126], &n[1127], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1127], &n[1128], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1128], &n[1129], &n[1105 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1129], &n[1130], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1130], &n[1131], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1131], &n[1132], &n[1133 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1132], &n[1133], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1133], &n[1134], &n[1131 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1134], &n[1135], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1135], &n[1136], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[1136], &n[1137], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1137], &n[1138], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1138], &n[1139], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1139], &n[1140], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1140], &n[1141], &n[1145 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1141], &n[1142], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1142], &n[1143], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1143], &n[1144], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1144], &n[1145], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1145], &n[1146], &n[1140 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1146], &n[1147], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1147], &n[1148], &n[1154 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1148], &n[1149], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1149], &n[1150], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1150], &n[1151], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1151], &n[1152], &n[1153 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1152], &n[1153], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1153], &n[1154], &n[1151 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1154], &n[1155], &n[1147 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1155], &n[1156], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1156], &n[1157], &n[1194 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1157], &n[1158], &n[1159 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1158], &n[1159], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1159], &n[1160], &n[1157 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1160], &n[1161], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1161], &n[1162], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1162], &n[1163], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1163], &n[1164], &n[1165 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1164], &n[1165], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1165], &n[1166], &n[1163 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1166], &n[1167], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1167], &n[1168], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1168], &n[1169], &n[1170 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1169], &n[1170], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1170], &n[1171], &n[1168 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1171], &n[1172], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1172], &n[1173], &n[1180 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1173], &n[1174], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1174], &n[1175], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1175], &n[1176], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1176], &n[1177], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1177], &n[1178], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1178], &n[1179], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1179], &n[1180], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1180], &n[1181], &n[1172 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1181], &n[1182], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1182], &n[1183], &n[1187 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1183], &n[1184], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1184], &n[1185], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1185], &n[1186], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1186], &n[1187], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1187], &n[1188], &n[1182 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1188], &n[1189], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1189], &n[1190], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1190], &n[1191], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1191], &n[1192], &n[1193 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1192], &n[1193], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1193], &n[1194], &n[1191 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1194], &n[1195], &n[1156 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1195], &n[1196], &n[1197 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1196], &n[1197], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1197], &n[1198], &n[1195 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1198], &n[1199], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1199], &n[1200], &n[1201 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1200], &n[1201], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1201], &n[1202], &n[1199 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1202], &n[1203], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1203], &n[1204], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1204], &n[1205], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1205], &n[1206], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1206], &n[1207], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1207], &n[1208], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1208], &n[1209], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1209], &n[1210], &n[1227 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1210], &n[1211], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1211], &n[1212], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1212], &n[1213], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1213], &n[1214], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1214], &n[1215], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1215], &n[1216], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1216], &n[1217], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1217], &n[1218], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1218], &n[1219], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1219], &n[1220], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1220], &n[1221], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1221], &n[1222], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1222], &n[1223], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1223], &n[1224], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1224], &n[1225], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1225], &n[1226], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1226], &n[1227], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1227], &n[1228], &n[1209 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1228], &n[1229], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1229], &n[1230], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1230], &n[1231], &n[1232 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1231], &n[1232], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1232], &n[1233], &n[1230 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1233], &n[1234], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1234], &n[1235], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[1235], &n[1236], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1236], &n[1237], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1237], &n[1238], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1238], &n[1239], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1239], &n[1240], &n[1244 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1240], &n[1241], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1241], &n[1242], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1242], &n[1243], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1243], &n[1244], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1244], &n[1245], &n[1239 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1245], &n[1246], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1246], &n[1247], &n[1253 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1247], &n[1248], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1248], &n[1249], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1249], &n[1250], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1250], &n[1251], &n[1252 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1251], &n[1252], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1252], &n[1253], &n[1250 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1253], &n[1254], &n[1246 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1254], &n[1255], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1255], &n[1256], &n[1293 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1256], &n[1257], &n[1258 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1257], &n[1258], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1258], &n[1259], &n[1256 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1259], &n[1260], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1260], &n[1261], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1261], &n[1262], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1262], &n[1263], &n[1264 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1263], &n[1264], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1264], &n[1265], &n[1262 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1265], &n[1266], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1266], &n[1267], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1267], &n[1268], &n[1269 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1268], &n[1269], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1269], &n[1270], &n[1267 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1270], &n[1271], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1271], &n[1272], &n[1279 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1272], &n[1273], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1273], &n[1274], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1274], &n[1275], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1275], &n[1276], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1276], &n[1277], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1277], &n[1278], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1278], &n[1279], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1279], &n[1280], &n[1271 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1280], &n[1281], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1281], &n[1282], &n[1286 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1282], &n[1283], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1283], &n[1284], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1284], &n[1285], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1285], &n[1286], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1286], &n[1287], &n[1281 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1287], &n[1288], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1288], &n[1289], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1289], &n[1290], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1290], &n[1291], &n[1292 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1291], &n[1292], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1292], &n[1293], &n[1290 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1293], &n[1294], &n[1255 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1294], &n[1295], &n[1296 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1295], &n[1296], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1296], &n[1297], &n[1294 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1297], &n[1298], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1298], &n[1299], &n[1300 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1299], &n[1300], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1300], &n[1301], &n[1298 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1301], &n[1302], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1302], &n[1303], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1303], &n[1304], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1304], &n[1305], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1305], &n[1306], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1306], &n[1307], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1307], &n[1308], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1308], &n[1309], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1309], &n[1310], &n[1327 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1310], &n[1311], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1311], &n[1312], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1312], &n[1313], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1313], &n[1314], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1314], &n[1315], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1315], &n[1316], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1316], &n[1317], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1317], &n[1318], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1318], &n[1319], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1319], &n[1320], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1320], &n[1321], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1321], &n[1322], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1322], &n[1323], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1323], &n[1324], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1324], &n[1325], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1325], &n[1326], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1326], &n[1327], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1327], &n[1328], &n[1309 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1328], &n[1329], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1329], &n[1330], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1330], &n[1331], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1331], &n[1332], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1332], &n[1333], &n[1334 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1333], &n[1334], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1334], &n[1335], &n[1332 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1335], &n[1336], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1336], &n[1337], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[1337], &n[1338], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1338], &n[1339], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1339], &n[1340], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1340], &n[1341], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1341], &n[1342], &n[1346 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1342], &n[1343], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1343], &n[1344], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1344], &n[1345], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1345], &n[1346], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1346], &n[1347], &n[1341 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1347], &n[1348], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1348], &n[1349], &n[1355 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1349], &n[1350], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1350], &n[1351], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1351], &n[1352], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1352], &n[1353], &n[1354 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1353], &n[1354], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1354], &n[1355], &n[1352 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1355], &n[1356], &n[1348 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1356], &n[1357], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1357], &n[1358], &n[1395 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1358], &n[1359], &n[1360 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1359], &n[1360], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1360], &n[1361], &n[1358 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1361], &n[1362], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1362], &n[1363], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1363], &n[1364], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1364], &n[1365], &n[1366 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1365], &n[1366], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1366], &n[1367], &n[1364 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1367], &n[1368], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1368], &n[1369], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1369], &n[1370], &n[1371 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1370], &n[1371], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1371], &n[1372], &n[1369 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1372], &n[1373], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1373], &n[1374], &n[1381 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1374], &n[1375], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1375], &n[1376], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1376], &n[1377], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1377], &n[1378], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1378], &n[1379], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1379], &n[1380], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1380], &n[1381], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1381], &n[1382], &n[1373 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1382], &n[1383], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1383], &n[1384], &n[1388 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1384], &n[1385], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1385], &n[1386], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1386], &n[1387], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1387], &n[1388], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1388], &n[1389], &n[1383 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1389], &n[1390], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1390], &n[1391], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1391], &n[1392], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1392], &n[1393], &n[1394 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1393], &n[1394], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1394], &n[1395], &n[1392 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1395], &n[1396], &n[1357 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1396], &n[1397], &n[1398 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1397], &n[1398], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1398], &n[1399], &n[1396 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1399], &n[1400], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1400], &n[1401], &n[1402 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1401], &n[1402], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1402], &n[1403], &n[1400 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1403], &n[1404], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1404], &n[1405], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1405], &n[1406], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1406], &n[1407], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1407], &n[1408], &n[1424 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1408], &n[1409], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1409], &n[1410], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1410], &n[1411], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1411], &n[1412], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1412], &n[1413], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1413], &n[1414], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1414], &n[1415], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1415], &n[1416], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1416], &n[1417], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1417], &n[1418], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1418], &n[1419], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1419], &n[1420], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1420], &n[1421], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1421], &n[1422], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1422], &n[1423], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1423], &n[1424], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1424], &n[1425], &n[1407 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1425], &n[1426], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1426], &n[1427], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1427], &n[1428], &n[1429 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1428], &n[1429], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1429], &n[1430], &n[1427 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1430], &n[1431], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1431], &n[1432], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[1432], &n[1433], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1433], &n[1434], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1434], &n[1435], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1435], &n[1436], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1436], &n[1437], &n[1441 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1437], &n[1438], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1438], &n[1439], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1439], &n[1440], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1440], &n[1441], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1441], &n[1442], &n[1436 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1442], &n[1443], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1443], &n[1444], &n[1450 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1444], &n[1445], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1445], &n[1446], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1446], &n[1447], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1447], &n[1448], &n[1449 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1448], &n[1449], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1449], &n[1450], &n[1447 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1450], &n[1451], &n[1443 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1451], &n[1452], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1452], &n[1453], &n[1490 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1453], &n[1454], &n[1455 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1454], &n[1455], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1455], &n[1456], &n[1453 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1456], &n[1457], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1457], &n[1458], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1458], &n[1459], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1459], &n[1460], &n[1461 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1460], &n[1461], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1461], &n[1462], &n[1459 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1462], &n[1463], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1463], &n[1464], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1464], &n[1465], &n[1466 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1465], &n[1466], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1466], &n[1467], &n[1464 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1467], &n[1468], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1468], &n[1469], &n[1476 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1469], &n[1470], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1470], &n[1471], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1471], &n[1472], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1472], &n[1473], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1473], &n[1474], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1474], &n[1475], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1475], &n[1476], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1476], &n[1477], &n[1468 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1477], &n[1478], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1478], &n[1479], &n[1483 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1479], &n[1480], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1480], &n[1481], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1481], &n[1482], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1482], &n[1483], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1483], &n[1484], &n[1478 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1484], &n[1485], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1485], &n[1486], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1486], &n[1487], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1487], &n[1488], &n[1489 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1488], &n[1489], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1489], &n[1490], &n[1487 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1490], &n[1491], &n[1452 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1491], &n[1492], &n[1493 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1492], &n[1493], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1493], &n[1494], &n[1491 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1494], &n[1495], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1495], &n[1496], &n[1497 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1496], &n[1497], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1497], &n[1498], &n[1495 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1498], &n[1499], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1499], &n[1500], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1500], &n[1501], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1501], &n[1502], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1502], &n[1503], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1503], &n[1504], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1504], &n[1505], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1505], &n[1506], &n[1524 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1506], &n[1507], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1507], &n[1508], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1508], &n[1509], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1509], &n[1510], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1510], &n[1511], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1511], &n[1512], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1512], &n[1513], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1513], &n[1514], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1514], &n[1515], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1515], &n[1516], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1516], &n[1517], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1517], &n[1518], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1518], &n[1519], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1519], &n[1520], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1520], &n[1521], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1521], &n[1522], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1522], &n[1523], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1523], &n[1524], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1524], &n[1525], &n[1505 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1525], &n[1526], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1526], &n[1527], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1527], &n[1528], &n[1529 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1528], &n[1529], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1529], &n[1530], &n[1527 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1530], &n[1531], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1531], &n[1532], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[1532], &n[1533], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1533], &n[1534], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1534], &n[1535], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1535], &n[1536], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1536], &n[1537], &n[1541 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1537], &n[1538], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1538], &n[1539], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1539], &n[1540], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1540], &n[1541], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1541], &n[1542], &n[1536 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1542], &n[1543], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1543], &n[1544], &n[1550 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1544], &n[1545], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1545], &n[1546], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1546], &n[1547], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1547], &n[1548], &n[1549 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1548], &n[1549], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1549], &n[1550], &n[1547 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1550], &n[1551], &n[1543 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1551], &n[1552], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1552], &n[1553], &n[1590 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1553], &n[1554], &n[1555 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1554], &n[1555], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1555], &n[1556], &n[1553 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1556], &n[1557], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1557], &n[1558], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1558], &n[1559], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1559], &n[1560], &n[1561 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1560], &n[1561], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1561], &n[1562], &n[1559 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1562], &n[1563], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1563], &n[1564], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1564], &n[1565], &n[1566 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1565], &n[1566], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1566], &n[1567], &n[1564 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1567], &n[1568], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1568], &n[1569], &n[1576 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1569], &n[1570], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1570], &n[1571], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1571], &n[1572], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1572], &n[1573], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1573], &n[1574], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1574], &n[1575], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1575], &n[1576], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1576], &n[1577], &n[1568 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1577], &n[1578], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1578], &n[1579], &n[1583 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1579], &n[1580], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1580], &n[1581], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1581], &n[1582], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1582], &n[1583], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1583], &n[1584], &n[1578 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1584], &n[1585], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1585], &n[1586], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1586], &n[1587], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1587], &n[1588], &n[1589 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1588], &n[1589], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1589], &n[1590], &n[1587 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1590], &n[1591], &n[1552 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1591], &n[1592], &n[1593 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1592], &n[1593], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1593], &n[1594], &n[1591 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1594], &n[1595], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1595], &n[1596], &n[1597 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1596], &n[1597], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1597], &n[1598], &n[1595 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1598], &n[1599], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1599], &n[1600], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1600], &n[1601], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1601], &n[1602], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1602], &n[1603], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1603], &n[1604], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1604], &n[1605], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1605], &n[1606], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1606], &n[1607], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1607], &n[1608], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1608], &n[1609], &n[1623 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1609], &n[1610], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1610], &n[1611], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1611], &n[1612], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1612], &n[1613], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1613], &n[1614], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1614], &n[1615], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1615], &n[1616], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1616], &n[1617], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1617], &n[1618], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1618], &n[1619], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1619], &n[1620], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1620], &n[1621], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1621], &n[1622], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1622], &n[1623], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1623], &n[1624], &n[1608 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1624], &n[1625], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1625], &n[1626], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1626], &n[1627], &n[1628 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1627], &n[1628], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1628], &n[1629], &n[1626 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1629], &n[1630], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1630], &n[1631], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[1631], &n[1632], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1632], &n[1633], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1633], &n[1634], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1634], &n[1635], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1635], &n[1636], &n[1640 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1636], &n[1637], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1637], &n[1638], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1638], &n[1639], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1639], &n[1640], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1640], &n[1641], &n[1635 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1641], &n[1642], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1642], &n[1643], &n[1649 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1643], &n[1644], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1644], &n[1645], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1645], &n[1646], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1646], &n[1647], &n[1648 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1647], &n[1648], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1648], &n[1649], &n[1646 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1649], &n[1650], &n[1642 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1650], &n[1651], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1651], &n[1652], &n[1689 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1652], &n[1653], &n[1654 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1653], &n[1654], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1654], &n[1655], &n[1652 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1655], &n[1656], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1656], &n[1657], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1657], &n[1658], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1658], &n[1659], &n[1660 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1659], &n[1660], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1660], &n[1661], &n[1658 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1661], &n[1662], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1662], &n[1663], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1663], &n[1664], &n[1665 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1664], &n[1665], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1665], &n[1666], &n[1663 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1666], &n[1667], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1667], &n[1668], &n[1675 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1668], &n[1669], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1669], &n[1670], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1670], &n[1671], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1671], &n[1672], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1672], &n[1673], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1673], &n[1674], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1674], &n[1675], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1675], &n[1676], &n[1667 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1676], &n[1677], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1677], &n[1678], &n[1682 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1678], &n[1679], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1679], &n[1680], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1680], &n[1681], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1681], &n[1682], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1682], &n[1683], &n[1677 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1683], &n[1684], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1684], &n[1685], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1685], &n[1686], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1686], &n[1687], &n[1688 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1687], &n[1688], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1688], &n[1689], &n[1686 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1689], &n[1690], &n[1651 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1690], &n[1691], &n[1692 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1691], &n[1692], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1692], &n[1693], &n[1690 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1693], &n[1694], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1694], &n[1695], &n[1696 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1695], &n[1696], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1696], &n[1697], &n[1694 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1697], &n[1698], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1698], &n[1699], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1699], &n[1700], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1700], &n[1701], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1701], &n[1702], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1702], &n[1703], &n[1725 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1703], &n[1704], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1704], &n[1705], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1705], &n[1706], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1706], &n[1707], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1707], &n[1708], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1708], &n[1709], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1709], &n[1710], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1710], &n[1711], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1711], &n[1712], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1712], &n[1713], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1713], &n[1714], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1714], &n[1715], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1715], &n[1716], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1716], &n[1717], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1717], &n[1718], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1718], &n[1719], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1719], &n[1720], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1720], &n[1721], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1721], &n[1722], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1722], &n[1723], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1723], &n[1724], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1724], &n[1725], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1725], &n[1726], &n[1702 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1726], &n[1727], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1727], &n[1728], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1728], &n[1729], &n[1730 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1729], &n[1730], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1730], &n[1731], &n[1728 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1731], &n[1732], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1732], &n[1733], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[1733], &n[1734], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1734], &n[1735], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1735], &n[1736], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1736], &n[1737], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1737], &n[1738], &n[1742 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1738], &n[1739], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1739], &n[1740], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1740], &n[1741], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1741], &n[1742], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1742], &n[1743], &n[1737 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1743], &n[1744], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1744], &n[1745], &n[1751 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1745], &n[1746], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1746], &n[1747], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1747], &n[1748], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1748], &n[1749], &n[1750 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1749], &n[1750], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1750], &n[1751], &n[1748 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1751], &n[1752], &n[1744 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1752], &n[1753], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1753], &n[1754], &n[1791 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1754], &n[1755], &n[1756 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1755], &n[1756], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1756], &n[1757], &n[1754 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1757], &n[1758], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1758], &n[1759], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1759], &n[1760], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1760], &n[1761], &n[1762 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1761], &n[1762], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1762], &n[1763], &n[1760 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1763], &n[1764], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1764], &n[1765], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1765], &n[1766], &n[1767 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1766], &n[1767], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1767], &n[1768], &n[1765 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1768], &n[1769], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1769], &n[1770], &n[1777 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1770], &n[1771], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1771], &n[1772], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1772], &n[1773], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1773], &n[1774], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1774], &n[1775], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1775], &n[1776], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1776], &n[1777], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1777], &n[1778], &n[1769 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1778], &n[1779], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1779], &n[1780], &n[1784 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1780], &n[1781], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1781], &n[1782], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1782], &n[1783], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1783], &n[1784], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1784], &n[1785], &n[1779 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1785], &n[1786], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1786], &n[1787], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1787], &n[1788], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1788], &n[1789], &n[1790 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1789], &n[1790], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1790], &n[1791], &n[1788 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1791], &n[1792], &n[1753 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1792], &n[1793], &n[1794 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1793], &n[1794], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1794], &n[1795], &n[1792 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1795], &n[1796], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1796], &n[1797], &n[1798 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1797], &n[1798], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1798], &n[1799], &n[1796 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1799], &n[1800], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1800], &n[1801], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1801], &n[1802], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1802], &n[1803], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1803], &n[1804], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1804], &n[1805], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1805], &n[1806], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1806], &n[1807], &n[1825 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1807], &n[1808], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1808], &n[1809], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1809], &n[1810], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1810], &n[1811], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1811], &n[1812], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1812], &n[1813], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1813], &n[1814], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1814], &n[1815], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1815], &n[1816], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1816], &n[1817], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1817], &n[1818], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1818], &n[1819], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1819], &n[1820], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1820], &n[1821], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1821], &n[1822], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1822], &n[1823], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1823], &n[1824], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1824], &n[1825], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1825], &n[1826], &n[1806 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1826], &n[1827], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1827], &n[1828], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1828], &n[1829], &n[1830 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1829], &n[1830], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1830], &n[1831], &n[1828 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1831], &n[1832], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1832], &n[1833], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[1833], &n[1834], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1834], &n[1835], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1835], &n[1836], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1836], &n[1837], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1837], &n[1838], &n[1842 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1838], &n[1839], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1839], &n[1840], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1840], &n[1841], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1841], &n[1842], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1842], &n[1843], &n[1837 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1843], &n[1844], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1844], &n[1845], &n[1851 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1845], &n[1846], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1846], &n[1847], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1847], &n[1848], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1848], &n[1849], &n[1850 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1849], &n[1850], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1850], &n[1851], &n[1848 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1851], &n[1852], &n[1844 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1852], &n[1853], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1853], &n[1854], &n[1891 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1854], &n[1855], &n[1856 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1855], &n[1856], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1856], &n[1857], &n[1854 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1857], &n[1858], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1858], &n[1859], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1859], &n[1860], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1860], &n[1861], &n[1862 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1861], &n[1862], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1862], &n[1863], &n[1860 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1863], &n[1864], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1864], &n[1865], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1865], &n[1866], &n[1867 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1866], &n[1867], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1867], &n[1868], &n[1865 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1868], &n[1869], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1869], &n[1870], &n[1877 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1870], &n[1871], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1871], &n[1872], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1872], &n[1873], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1873], &n[1874], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1874], &n[1875], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1875], &n[1876], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1876], &n[1877], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1877], &n[1878], &n[1869 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1878], &n[1879], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1879], &n[1880], &n[1884 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1880], &n[1881], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1881], &n[1882], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1882], &n[1883], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1883], &n[1884], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1884], &n[1885], &n[1879 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1885], &n[1886], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1886], &n[1887], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1887], &n[1888], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1888], &n[1889], &n[1890 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1889], &n[1890], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1890], &n[1891], &n[1888 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1891], &n[1892], &n[1853 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1892], &n[1893], &n[1894 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1893], &n[1894], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1894], &n[1895], &n[1892 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1895], &n[1896], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1896], &n[1897], &n[1898 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1897], &n[1898], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1898], &n[1899], &n[1896 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1899], &n[1900], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1900], &n[1901], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1901], &n[1902], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1902], &n[1903], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1903], &n[1904], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1904], &n[1905], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1905], &n[1906], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1906], &n[1907], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1907], &n[1908], &n[1925 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1908], &n[1909], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1909], &n[1910], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1910], &n[1911], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1911], &n[1912], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1912], &n[1913], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1913], &n[1914], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1914], &n[1915], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1915], &n[1916], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1916], &n[1917], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1917], &n[1918], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1918], &n[1919], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1919], &n[1920], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1920], &n[1921], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1921], &n[1922], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1922], &n[1923], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1923], &n[1924], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1924], &n[1925], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1925], &n[1926], &n[1907 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1926], &n[1927], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1927], &n[1928], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1928], &n[1929], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1929], &n[1930], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1930], &n[1931], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1931], &n[1932], &n[1933 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1932], &n[1933], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1933], &n[1934], &n[1931 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1934], &n[1935], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1935], &n[1936], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[1936], &n[1937], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1937], &n[1938], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1938], &n[1939], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1939], &n[1940], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1940], &n[1941], &n[1945 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1941], &n[1942], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1942], &n[1943], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1943], &n[1944], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1944], &n[1945], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1945], &n[1946], &n[1940 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1946], &n[1947], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1947], &n[1948], &n[1954 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1948], &n[1949], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1949], &n[1950], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1950], &n[1951], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1951], &n[1952], &n[1953 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1952], &n[1953], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1953], &n[1954], &n[1951 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1954], &n[1955], &n[1947 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1955], &n[1956], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1956], &n[1957], &n[1994 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1957], &n[1958], &n[1959 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1958], &n[1959], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1959], &n[1960], &n[1957 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1960], &n[1961], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1961], &n[1962], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1962], &n[1963], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1963], &n[1964], &n[1965 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1964], &n[1965], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1965], &n[1966], &n[1963 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1966], &n[1967], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1967], &n[1968], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1968], &n[1969], &n[1970 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1969], &n[1970], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1970], &n[1971], &n[1968 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1971], &n[1972], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1972], &n[1973], &n[1980 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1973], &n[1974], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1974], &n[1975], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1975], &n[1976], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1976], &n[1977], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1977], &n[1978], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1978], &n[1979], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1979], &n[1980], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1980], &n[1981], &n[1972 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1981], &n[1982], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1982], &n[1983], &n[1987 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1983], &n[1984], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[1984], &n[1985], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1985], &n[1986], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1986], &n[1987], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1987], &n[1988], &n[1982 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1988], &n[1989], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1989], &n[1990], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[1990], &n[1991], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1991], &n[1992], &n[1993 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1992], &n[1993], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1993], &n[1994], &n[1991 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1994], &n[1995], &n[1956 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1995], &n[1996], &n[1997 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[1996], &n[1997], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[1997], &n[1998], &n[1995 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[1998], &n[1999], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[1999], &n[2000], &n[2001 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2000], &n[2001], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2001], &n[2002], &n[1999 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2002], &n[2003], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2003], &n[2004], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2004], &n[2005], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2005], &n[2006], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2006], &n[2007], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2007], &n[2008], &n[2030 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2008], &n[2009], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2009], &n[2010], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2010], &n[2011], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2011], &n[2012], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2012], &n[2013], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2013], &n[2014], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2014], &n[2015], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2015], &n[2016], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2016], &n[2017], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2017], &n[2018], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2018], &n[2019], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2019], &n[2020], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2020], &n[2021], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2021], &n[2022], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2022], &n[2023], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2023], &n[2024], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2024], &n[2025], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2025], &n[2026], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2026], &n[2027], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2027], &n[2028], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2028], &n[2029], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2029], &n[2030], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2030], &n[2031], &n[2007 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2031], &n[2032], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2032], &n[2033], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2033], &n[2034], &n[2035 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2034], &n[2035], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2035], &n[2036], &n[2033 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2036], &n[2037], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2037], &n[2038], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[2038], &n[2039], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2039], &n[2040], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2040], &n[2041], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2041], &n[2042], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2042], &n[2043], &n[2047 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2043], &n[2044], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2044], &n[2045], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2045], &n[2046], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2046], &n[2047], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2047], &n[2048], &n[2042 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2048], &n[2049], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2049], &n[2050], &n[2056 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2050], &n[2051], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2051], &n[2052], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2052], &n[2053], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2053], &n[2054], &n[2055 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2054], &n[2055], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2055], &n[2056], &n[2053 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2056], &n[2057], &n[2049 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2057], &n[2058], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2058], &n[2059], &n[2096 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2059], &n[2060], &n[2061 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2060], &n[2061], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2061], &n[2062], &n[2059 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2062], &n[2063], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2063], &n[2064], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2064], &n[2065], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2065], &n[2066], &n[2067 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2066], &n[2067], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2067], &n[2068], &n[2065 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2068], &n[2069], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2069], &n[2070], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2070], &n[2071], &n[2072 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2071], &n[2072], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2072], &n[2073], &n[2070 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2073], &n[2074], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2074], &n[2075], &n[2082 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2075], &n[2076], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2076], &n[2077], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2077], &n[2078], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2078], &n[2079], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2079], &n[2080], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2080], &n[2081], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2081], &n[2082], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2082], &n[2083], &n[2074 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2083], &n[2084], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2084], &n[2085], &n[2089 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2085], &n[2086], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2086], &n[2087], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2087], &n[2088], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2088], &n[2089], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2089], &n[2090], &n[2084 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2090], &n[2091], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2091], &n[2092], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2092], &n[2093], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2093], &n[2094], &n[2095 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2094], &n[2095], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2095], &n[2096], &n[2093 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2096], &n[2097], &n[2058 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2097], &n[2098], &n[2099 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2098], &n[2099], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2099], &n[2100], &n[2097 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2100], &n[2101], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2101], &n[2102], &n[2103 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2102], &n[2103], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2103], &n[2104], &n[2101 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2104], &n[2105], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2105], &n[2106], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2106], &n[2107], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2107], &n[2108], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2108], &n[2109], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2109], &n[2110], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2110], &n[2111], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2111], &n[2112], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2112], &n[2113], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2113], &n[2114], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2114], &n[2115], &n[2128 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2115], &n[2116], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2116], &n[2117], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2117], &n[2118], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2118], &n[2119], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2119], &n[2120], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2120], &n[2121], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2121], &n[2122], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2122], &n[2123], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2123], &n[2124], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2124], &n[2125], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2125], &n[2126], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2126], &n[2127], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2127], &n[2128], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2128], &n[2129], &n[2114 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2129], &n[2130], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2130], &n[2131], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2131], &n[2132], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2132], &n[2133], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2133], &n[2134], &n[2135 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2134], &n[2135], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2135], &n[2136], &n[2133 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2136], &n[2137], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2137], &n[2138], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[2138], &n[2139], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2139], &n[2140], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2140], &n[2141], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2141], &n[2142], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2142], &n[2143], &n[2147 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2143], &n[2144], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2144], &n[2145], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2145], &n[2146], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2146], &n[2147], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2147], &n[2148], &n[2142 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2148], &n[2149], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2149], &n[2150], &n[2156 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2150], &n[2151], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2151], &n[2152], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2152], &n[2153], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2153], &n[2154], &n[2155 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2154], &n[2155], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2155], &n[2156], &n[2153 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2156], &n[2157], &n[2149 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2157], &n[2158], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2158], &n[2159], &n[2196 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2159], &n[2160], &n[2161 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2160], &n[2161], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2161], &n[2162], &n[2159 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2162], &n[2163], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2163], &n[2164], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2164], &n[2165], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2165], &n[2166], &n[2167 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2166], &n[2167], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2167], &n[2168], &n[2165 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2168], &n[2169], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2169], &n[2170], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2170], &n[2171], &n[2172 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2171], &n[2172], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2172], &n[2173], &n[2170 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2173], &n[2174], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2174], &n[2175], &n[2182 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2175], &n[2176], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2176], &n[2177], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2177], &n[2178], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2178], &n[2179], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2179], &n[2180], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2180], &n[2181], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2181], &n[2182], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2182], &n[2183], &n[2174 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2183], &n[2184], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2184], &n[2185], &n[2189 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2185], &n[2186], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2186], &n[2187], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2187], &n[2188], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2188], &n[2189], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2189], &n[2190], &n[2184 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2190], &n[2191], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2191], &n[2192], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2192], &n[2193], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2193], &n[2194], &n[2195 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2194], &n[2195], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2195], &n[2196], &n[2193 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2196], &n[2197], &n[2158 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2197], &n[2198], &n[2199 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2198], &n[2199], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2199], &n[2200], &n[2197 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2200], &n[2201], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2201], &n[2202], &n[2203 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2202], &n[2203], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2203], &n[2204], &n[2201 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2204], &n[2205], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2205], &n[2206], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2206], &n[2207], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2207], &n[2208], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2208], &n[2209], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2209], &n[2210], &n[2232 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2210], &n[2211], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2211], &n[2212], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2212], &n[2213], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2213], &n[2214], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2214], &n[2215], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2215], &n[2216], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2216], &n[2217], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2217], &n[2218], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2218], &n[2219], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2219], &n[2220], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2220], &n[2221], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2221], &n[2222], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2222], &n[2223], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2223], &n[2224], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2224], &n[2225], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2225], &n[2226], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2226], &n[2227], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2227], &n[2228], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2228], &n[2229], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2229], &n[2230], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2230], &n[2231], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2231], &n[2232], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2232], &n[2233], &n[2209 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2233], &n[2234], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2234], &n[2235], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2235], &n[2236], &n[2237 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2236], &n[2237], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2237], &n[2238], &n[2235 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2238], &n[2239], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2239], &n[2240], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[2240], &n[2241], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2241], &n[2242], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2242], &n[2243], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2243], &n[2244], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2244], &n[2245], &n[2249 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2245], &n[2246], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2246], &n[2247], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2247], &n[2248], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2248], &n[2249], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2249], &n[2250], &n[2244 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2250], &n[2251], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2251], &n[2252], &n[2258 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2252], &n[2253], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2253], &n[2254], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2254], &n[2255], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2255], &n[2256], &n[2257 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2256], &n[2257], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2257], &n[2258], &n[2255 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2258], &n[2259], &n[2251 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2259], &n[2260], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2260], &n[2261], &n[2298 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2261], &n[2262], &n[2263 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2262], &n[2263], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2263], &n[2264], &n[2261 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2264], &n[2265], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2265], &n[2266], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2266], &n[2267], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2267], &n[2268], &n[2269 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2268], &n[2269], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2269], &n[2270], &n[2267 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2270], &n[2271], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2271], &n[2272], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2272], &n[2273], &n[2274 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2273], &n[2274], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2274], &n[2275], &n[2272 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2275], &n[2276], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2276], &n[2277], &n[2284 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2277], &n[2278], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2278], &n[2279], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2279], &n[2280], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2280], &n[2281], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2281], &n[2282], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2282], &n[2283], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2283], &n[2284], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2284], &n[2285], &n[2276 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2285], &n[2286], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2286], &n[2287], &n[2291 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2287], &n[2288], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2288], &n[2289], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2289], &n[2290], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2290], &n[2291], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2291], &n[2292], &n[2286 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2292], &n[2293], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2293], &n[2294], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2294], &n[2295], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2295], &n[2296], &n[2297 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2296], &n[2297], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2297], &n[2298], &n[2295 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2298], &n[2299], &n[2260 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2299], &n[2300], &n[2301 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2300], &n[2301], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2301], &n[2302], &n[2299 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2302], &n[2303], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2303], &n[2304], &n[2305 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2304], &n[2305], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2305], &n[2306], &n[2303 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2306], &n[2307], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2307], &n[2308], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2308], &n[2309], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2309], &n[2310], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2310], &n[2311], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2311], &n[2312], &n[2334 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2312], &n[2313], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2313], &n[2314], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2314], &n[2315], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2315], &n[2316], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2316], &n[2317], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2317], &n[2318], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2318], &n[2319], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2319], &n[2320], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2320], &n[2321], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2321], &n[2322], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2322], &n[2323], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2323], &n[2324], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2324], &n[2325], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2325], &n[2326], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2326], &n[2327], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2327], &n[2328], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2328], &n[2329], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2329], &n[2330], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2330], &n[2331], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2331], &n[2332], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2332], &n[2333], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2333], &n[2334], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2334], &n[2335], &n[2311 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2335], &n[2336], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2336], &n[2337], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2337], &n[2338], &n[2339 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2338], &n[2339], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2339], &n[2340], &n[2337 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2340], &n[2341], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2341], &n[2342], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[2342], &n[2343], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2343], &n[2344], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2344], &n[2345], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2345], &n[2346], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2346], &n[2347], &n[2351 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2347], &n[2348], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2348], &n[2349], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2349], &n[2350], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2350], &n[2351], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2351], &n[2352], &n[2346 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2352], &n[2353], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2353], &n[2354], &n[2360 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2354], &n[2355], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2355], &n[2356], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2356], &n[2357], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2357], &n[2358], &n[2359 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2358], &n[2359], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2359], &n[2360], &n[2357 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2360], &n[2361], &n[2353 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2361], &n[2362], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2362], &n[2363], &n[2400 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2363], &n[2364], &n[2365 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2364], &n[2365], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2365], &n[2366], &n[2363 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2366], &n[2367], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2367], &n[2368], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2368], &n[2369], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2369], &n[2370], &n[2371 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2370], &n[2371], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2371], &n[2372], &n[2369 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2372], &n[2373], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2373], &n[2374], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2374], &n[2375], &n[2376 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2375], &n[2376], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2376], &n[2377], &n[2374 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2377], &n[2378], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2378], &n[2379], &n[2386 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2379], &n[2380], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2380], &n[2381], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2381], &n[2382], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2382], &n[2383], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2383], &n[2384], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2384], &n[2385], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2385], &n[2386], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2386], &n[2387], &n[2378 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2387], &n[2388], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2388], &n[2389], &n[2393 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2389], &n[2390], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2390], &n[2391], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2391], &n[2392], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2392], &n[2393], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2393], &n[2394], &n[2388 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2394], &n[2395], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2395], &n[2396], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2396], &n[2397], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2397], &n[2398], &n[2399 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2398], &n[2399], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2399], &n[2400], &n[2397 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2400], &n[2401], &n[2362 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2401], &n[2402], &n[2403 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2402], &n[2403], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2403], &n[2404], &n[2401 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2404], &n[2405], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2405], &n[2406], &n[2407 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2406], &n[2407], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2407], &n[2408], &n[2405 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2408], &n[2409], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2409], &n[2410], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2410], &n[2411], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2411], &n[2412], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2412], &n[2413], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2413], &n[2414], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2414], &n[2415], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2415], &n[2416], &n[2434 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2416], &n[2417], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2417], &n[2418], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2418], &n[2419], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2419], &n[2420], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2420], &n[2421], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2421], &n[2422], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2422], &n[2423], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2423], &n[2424], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2424], &n[2425], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2425], &n[2426], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2426], &n[2427], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2427], &n[2428], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2428], &n[2429], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2429], &n[2430], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2430], &n[2431], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2431], &n[2432], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2432], &n[2433], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2433], &n[2434], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2434], &n[2435], &n[2415 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2435], &n[2436], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2436], &n[2437], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2437], &n[2438], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2438], &n[2439], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2439], &n[2440], &n[2441 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2440], &n[2441], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2441], &n[2442], &n[2439 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2442], &n[2443], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2443], &n[2444], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[2444], &n[2445], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2445], &n[2446], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2446], &n[2447], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2447], &n[2448], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2448], &n[2449], &n[2453 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2449], &n[2450], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2450], &n[2451], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2451], &n[2452], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2452], &n[2453], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2453], &n[2454], &n[2448 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2454], &n[2455], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2455], &n[2456], &n[2462 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2456], &n[2457], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2457], &n[2458], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2458], &n[2459], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2459], &n[2460], &n[2461 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2460], &n[2461], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2461], &n[2462], &n[2459 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2462], &n[2463], &n[2455 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2463], &n[2464], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2464], &n[2465], &n[2502 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2465], &n[2466], &n[2467 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2466], &n[2467], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2467], &n[2468], &n[2465 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2468], &n[2469], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2469], &n[2470], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2470], &n[2471], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2471], &n[2472], &n[2473 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2472], &n[2473], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2473], &n[2474], &n[2471 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2474], &n[2475], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2475], &n[2476], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2476], &n[2477], &n[2478 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2477], &n[2478], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2478], &n[2479], &n[2476 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2479], &n[2480], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2480], &n[2481], &n[2488 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2481], &n[2482], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2482], &n[2483], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2483], &n[2484], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2484], &n[2485], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2485], &n[2486], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2486], &n[2487], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2487], &n[2488], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2488], &n[2489], &n[2480 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2489], &n[2490], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2490], &n[2491], &n[2495 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2491], &n[2492], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2492], &n[2493], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2493], &n[2494], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2494], &n[2495], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2495], &n[2496], &n[2490 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2496], &n[2497], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2497], &n[2498], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2498], &n[2499], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2499], &n[2500], &n[2501 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2500], &n[2501], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2501], &n[2502], &n[2499 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2502], &n[2503], &n[2464 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2503], &n[2504], &n[2505 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2504], &n[2505], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2505], &n[2506], &n[2503 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2506], &n[2507], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2507], &n[2508], &n[2509 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2508], &n[2509], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2509], &n[2510], &n[2507 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2510], &n[2511], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2511], &n[2512], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2512], &n[2513], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2513], &n[2514], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2514], &n[2515], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2515], &n[2516], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2516], &n[2517], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2517], &n[2518], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2518], &n[2519], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2519], &n[2520], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2520], &n[2521], &n[2534 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2521], &n[2522], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2522], &n[2523], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2523], &n[2524], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2524], &n[2525], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2525], &n[2526], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2526], &n[2527], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2527], &n[2528], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2528], &n[2529], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2529], &n[2530], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2530], &n[2531], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2531], &n[2532], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2532], &n[2533], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2533], &n[2534], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2534], &n[2535], &n[2520 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2535], &n[2536], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2536], &n[2537], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2537], &n[2538], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2538], &n[2539], &n[2540 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2539], &n[2540], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2540], &n[2541], &n[2538 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2541], &n[2542], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2542], &n[2543], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[2543], &n[2544], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2544], &n[2545], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2545], &n[2546], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2546], &n[2547], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2547], &n[2548], &n[2552 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2548], &n[2549], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2549], &n[2550], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2550], &n[2551], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2551], &n[2552], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2552], &n[2553], &n[2547 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2553], &n[2554], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2554], &n[2555], &n[2561 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2555], &n[2556], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2556], &n[2557], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2557], &n[2558], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2558], &n[2559], &n[2560 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2559], &n[2560], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2560], &n[2561], &n[2558 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2561], &n[2562], &n[2554 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2562], &n[2563], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2563], &n[2564], &n[2601 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2564], &n[2565], &n[2566 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2565], &n[2566], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2566], &n[2567], &n[2564 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2567], &n[2568], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2568], &n[2569], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2569], &n[2570], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2570], &n[2571], &n[2572 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2571], &n[2572], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2572], &n[2573], &n[2570 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2573], &n[2574], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2574], &n[2575], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2575], &n[2576], &n[2577 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2576], &n[2577], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2577], &n[2578], &n[2575 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2578], &n[2579], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2579], &n[2580], &n[2587 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2580], &n[2581], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2581], &n[2582], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2582], &n[2583], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2583], &n[2584], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2584], &n[2585], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2585], &n[2586], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2586], &n[2587], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2587], &n[2588], &n[2579 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2588], &n[2589], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2589], &n[2590], &n[2594 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2590], &n[2591], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2591], &n[2592], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2592], &n[2593], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2593], &n[2594], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2594], &n[2595], &n[2589 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2595], &n[2596], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2596], &n[2597], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2597], &n[2598], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2598], &n[2599], &n[2600 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2599], &n[2600], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2600], &n[2601], &n[2598 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2601], &n[2602], &n[2563 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2602], &n[2603], &n[2604 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2603], &n[2604], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2604], &n[2605], &n[2602 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2605], &n[2606], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2606], &n[2607], &n[2608 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2607], &n[2608], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2608], &n[2609], &n[2606 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2609], &n[2610], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2610], &n[2611], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2611], &n[2612], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2612], &n[2613], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2613], &n[2614], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2614], &n[2615], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2615], &n[2616], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2616], &n[2617], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2617], &n[2618], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2618], &n[2619], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2619], &n[2620], &n[2633 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2620], &n[2621], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2621], &n[2622], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2622], &n[2623], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2623], &n[2624], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2624], &n[2625], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2625], &n[2626], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2626], &n[2627], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2627], &n[2628], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2628], &n[2629], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2629], &n[2630], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2630], &n[2631], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2631], &n[2632], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2632], &n[2633], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2633], &n[2634], &n[2619 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2634], &n[2635], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2635], &n[2636], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2636], &n[2637], &n[2638 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2637], &n[2638], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2638], &n[2639], &n[2636 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2639], &n[2640], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2640], &n[2641], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[2641], &n[2642], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2642], &n[2643], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2643], &n[2644], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2644], &n[2645], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2645], &n[2646], &n[2650 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2646], &n[2647], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2647], &n[2648], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2648], &n[2649], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2649], &n[2650], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2650], &n[2651], &n[2645 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2651], &n[2652], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2652], &n[2653], &n[2659 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2653], &n[2654], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2654], &n[2655], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2655], &n[2656], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2656], &n[2657], &n[2658 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2657], &n[2658], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2658], &n[2659], &n[2656 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2659], &n[2660], &n[2652 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2660], &n[2661], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2661], &n[2662], &n[2699 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2662], &n[2663], &n[2664 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2663], &n[2664], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2664], &n[2665], &n[2662 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2665], &n[2666], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2666], &n[2667], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2667], &n[2668], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2668], &n[2669], &n[2670 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2669], &n[2670], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2670], &n[2671], &n[2668 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2671], &n[2672], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2672], &n[2673], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2673], &n[2674], &n[2675 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2674], &n[2675], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2675], &n[2676], &n[2673 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2676], &n[2677], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2677], &n[2678], &n[2685 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2678], &n[2679], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2679], &n[2680], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2680], &n[2681], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2681], &n[2682], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2682], &n[2683], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2683], &n[2684], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2684], &n[2685], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2685], &n[2686], &n[2677 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2686], &n[2687], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2687], &n[2688], &n[2692 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2688], &n[2689], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2689], &n[2690], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2690], &n[2691], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2691], &n[2692], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2692], &n[2693], &n[2687 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2693], &n[2694], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2694], &n[2695], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2695], &n[2696], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2696], &n[2697], &n[2698 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2697], &n[2698], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2698], &n[2699], &n[2696 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2699], &n[2700], &n[2661 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2700], &n[2701], &n[2702 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2701], &n[2702], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2702], &n[2703], &n[2700 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2703], &n[2704], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2704], &n[2705], &n[2706 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2705], &n[2706], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2706], &n[2707], &n[2704 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2707], &n[2708], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2708], &n[2709], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2709], &n[2710], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2710], &n[2711], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2711], &n[2712], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2712], &n[2713], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2713], &n[2714], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2714], &n[2715], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2715], &n[2716], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2716], &n[2717], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2717], &n[2718], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2718], &n[2719], &n[2733 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2719], &n[2720], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2720], &n[2721], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2721], &n[2722], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2722], &n[2723], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2723], &n[2724], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2724], &n[2725], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2725], &n[2726], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2726], &n[2727], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2727], &n[2728], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2728], &n[2729], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2729], &n[2730], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2730], &n[2731], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2731], &n[2732], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2732], &n[2733], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2733], &n[2734], &n[2718 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2734], &n[2735], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2735], &n[2736], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2736], &n[2737], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2737], &n[2738], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2738], &n[2739], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2739], &n[2740], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2740], &n[2741], &n[2742 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2741], &n[2742], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2742], &n[2743], &n[2740 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2743], &n[2744], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2744], &n[2745], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i] = <- in
        w.Done()
        }
    }(&n[2745], &n[2746], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2746], &n[2747], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2747], &n[2748], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2748], &n[2749], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2749], &n[2750], &n[2754 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2750], &n[2751], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2751], &n[2752], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2752], &n[2753], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2753], &n[2754], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2754], &n[2755], &n[2749 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2755], &n[2756], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2756], &n[2757], &n[2763 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2757], &n[2758], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2758], &n[2759], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2759], &n[2760], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2760], &n[2761], &n[2762 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2761], &n[2762], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2762], &n[2763], &n[2760 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2763], &n[2764], &n[2756 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2764], &n[2765], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2765], &n[2766], &n[2803 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2766], &n[2767], &n[2768 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2767], &n[2768], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2768], &n[2769], &n[2766 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2769], &n[2770], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2770], &n[2771], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2771], &n[2772], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2772], &n[2773], &n[2774 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2773], &n[2774], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2774], &n[2775], &n[2772 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2775], &n[2776], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2776], &n[2777], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2777], &n[2778], &n[2779 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2778], &n[2779], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2779], &n[2780], &n[2777 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2780], &n[2781], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2781], &n[2782], &n[2789 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2782], &n[2783], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2783], &n[2784], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2784], &n[2785], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2785], &n[2786], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2786], &n[2787], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2787], &n[2788], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2788], &n[2789], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2789], &n[2790], &n[2781 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2790], &n[2791], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2791], &n[2792], &n[2796 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2792], &n[2793], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2793], &n[2794], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2794], &n[2795], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2795], &n[2796], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2796], &n[2797], &n[2791 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2797], &n[2798], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2798], &n[2799], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2799], &n[2800], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2800], &n[2801], &n[2802 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2801], &n[2802], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2802], &n[2803], &n[2800 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2803], &n[2804], &n[2765 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2804], &n[2805], &n[2806 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2805], &n[2806], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2806], &n[2807], &n[2804 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2807], &n[2808], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2808], &n[2809], &n[2810 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2809], &n[2810], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2810], &n[2811], &n[2808 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2811], &n[2812], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2812], &n[2813], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2813], &n[2814], &n[2821 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2814], &n[2815], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2815], &n[2816], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2816], &n[2817], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2817], &n[2818], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2818], &n[2819], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2819], &n[2820], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2820], &n[2821], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2821], &n[2822], &n[2813 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2822], &n[2823], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2823], &n[2824], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2824], &n[2825], &n[2831 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2825], &n[2826], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2826], &n[2827], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2827], &n[2828], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2828], &n[2829], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2829], &n[2830], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2830], &n[2831], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2831], &n[2832], &n[2824 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2832], &n[2833], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2833], &n[2834], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2834], &n[2835], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2835], &n[2836], &n[2837 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2836], &n[2837], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2837], &n[2838], &n[2835 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2838], &n[2839], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2839], &n[2840], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2840], &n[2841], &n[2847 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2841], &n[2842], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2842], &n[2843], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2843], &n[2844], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2844], &n[2845], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2845], &n[2846], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2846], &n[2847], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2847], &n[2848], &n[2840 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2848], &n[2849], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2849], &n[2850], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2850], &n[2851], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2851], &n[2852], &n[2853 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2852], &n[2853], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2853], &n[2854], &n[2851 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2854], &n[2855], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2855], &n[2856], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2856], &n[2857], &n[3009 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2857], &n[2858], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2858], &n[2859], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2859], &n[2860], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2860], &n[2861], &n[2862 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2861], &n[2862], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2862], &n[2863], &n[2860 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2863], &n[2864], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2864], &n[2865], &n[2866 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2865], &n[2866], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2866], &n[2867], &n[2864 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2867], &n[2868], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2868], &n[2869], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2869], &n[2870], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2870], &n[2871], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2871], &n[2872], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2872], &n[2873], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2873], &n[2874], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2874], &n[2875], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2875], &n[2876], &n[2890 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2876], &n[2877], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2877], &n[2878], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2878], &n[2879], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2879], &n[2880], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2880], &n[2881], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2881], &n[2882], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2882], &n[2883], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2883], &n[2884], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2884], &n[2885], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2885], &n[2886], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2886], &n[2887], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2887], &n[2888], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2888], &n[2889], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2889], &n[2890], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2890], &n[2891], &n[2875 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2891], &n[2892], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2892], &n[2893], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[2893], &n[2894], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2894], &n[2895], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2895], &n[2896], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2896], &n[2897], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2897], &n[2898], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2898], &n[2899], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2899], &n[2900], &n[2914 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2900], &n[2901], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2901], &n[2902], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2902], &n[2903], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2903], &n[2904], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2904], &n[2905], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2905], &n[2906], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2906], &n[2907], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2907], &n[2908], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2908], &n[2909], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2909], &n[2910], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2910], &n[2911], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2911], &n[2912], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2912], &n[2913], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2913], &n[2914], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2914], &n[2915], &n[2899 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2915], &n[2916], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[2916], &n[2917], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2917], &n[2918], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2918], &n[2919], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2919], &n[2920], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[2920], &n[2921], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[2921], &n[2922], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2922], &n[2923], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2923], &n[2924], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2924], &n[2925], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2925], &n[2926], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2926], &n[2927], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2927], &n[2928], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2928], &n[2929], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2929], &n[2930], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2930], &n[2931], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2931], &n[2932], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2932], &n[2933], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2933], &n[2934], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2934], &n[2935], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[2935], &n[2936], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2936], &n[2937], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2937], &n[2938], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[2938], &n[2939], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2939], &n[2940], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2940], &n[2941], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2941], &n[2942], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2942], &n[2943], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2943], &n[2944], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2944], &n[2945], &n[2952 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2945], &n[2946], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2946], &n[2947], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2947], &n[2948], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2948], &n[2949], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2949], &n[2950], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2950], &n[2951], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2951], &n[2952], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2952], &n[2953], &n[2944 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2953], &n[2954], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2954], &n[2955], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[2955], &n[2956], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2956], &n[2957], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2957], &n[2958], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2958], &n[2959], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2959], &n[2960], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2960], &n[2961], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2961], &n[2962], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2962], &n[2963], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2963], &n[2964], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2964], &n[2965], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2965], &n[2966], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2966], &n[2967], &n[2979 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2967], &n[2968], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2968], &n[2969], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2969], &n[2970], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2970], &n[2971], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2971], &n[2972], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2972], &n[2973], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2973], &n[2974], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2974], &n[2975], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2975], &n[2976], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2976], &n[2977], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2977], &n[2978], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2978], &n[2979], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2979], &n[2980], &n[2966 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2980], &n[2981], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2981], &n[2982], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2982], &n[2983], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[2983], &n[2984], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2984], &n[2985], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2985], &n[2986], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2986], &n[2987], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[2987], &n[2988], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[2988], &n[2989], &n[2999 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2989], &n[2990], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[2990], &n[2991], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2991], &n[2992], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2992], &n[2993], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2993], &n[2994], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2994], &n[2995], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2995], &n[2996], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2996], &n[2997], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[2997], &n[2998], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[2998], &n[2999], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[2999], &n[3000], &n[2988 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3000], &n[3001], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3001], &n[3002], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3002], &n[3003], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[3003], &n[3004], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3004], &n[3005], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3005], &n[3006], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[3006], &n[3007], &n[3008 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3007], &n[3008], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[3008], &n[3009], &n[3006 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[3009], &n[3010], &n[2856 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3010], &n[3011], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[3011], &n[3012], &n[3132 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3012], &n[3013], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[3013], &n[3014], &n[3015 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3014], &n[3015], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[3015], &n[3016], &n[3013 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3016], &n[3017], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[3017], &n[3018], &n[3019 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3018], &n[3019], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[3019], &n[3020], &n[3017 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3020], &n[3021], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3021], &n[3022], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3022], &n[3023], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3023], &n[3024], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3024], &n[3025], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3025], &n[3026], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3026], &n[3027], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3027], &n[3028], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3028], &n[3029], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[3029], &n[3030], &n[3045 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3030], &n[3031], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3031], &n[3032], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3032], &n[3033], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3033], &n[3034], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3034], &n[3035], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3035], &n[3036], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3036], &n[3037], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3037], &n[3038], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3038], &n[3039], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3039], &n[3040], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3040], &n[3041], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3041], &n[3042], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3042], &n[3043], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3043], &n[3044], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3044], &n[3045], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[3045], &n[3046], &n[3029 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3046], &n[3047], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3047], &n[3048], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3048], &n[3049], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3049], &n[3050], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[3050], &n[3051], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3051], &n[3052], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3052], &n[3053], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3053], &n[3054], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3054], &n[3055], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[3055], &n[3056], &n[3068 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3056], &n[3057], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3057], &n[3058], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3058], &n[3059], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3059], &n[3060], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3060], &n[3061], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3061], &n[3062], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3062], &n[3063], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3063], &n[3064], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3064], &n[3065], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3065], &n[3066], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3066], &n[3067], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3067], &n[3068], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[3068], &n[3069], &n[3055 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3069], &n[3070], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[3070], &n[3071], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3071], &n[3072], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3072], &n[3073], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3073], &n[3074], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[3074], &n[3075], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3075], &n[3076], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[3076], &n[3077], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3077], &n[3078], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3078], &n[3079], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3079], &n[3080], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3080], &n[3081], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3081], &n[3082], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3082], &n[3083], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3083], &n[3084], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[3084], &n[3085], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3085], &n[3086], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3086], &n[3087], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3087], &n[3088], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3088], &n[3089], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3089], &n[3090], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3090], &n[3091], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3091], &n[3092], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3092], &n[3093], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[3093], &n[3094], &n[3107 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3094], &n[3095], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3095], &n[3096], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3096], &n[3097], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3097], &n[3098], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3098], &n[3099], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3099], &n[3100], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3100], &n[3101], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3101], &n[3102], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3102], &n[3103], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3103], &n[3104], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3104], &n[3105], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3105], &n[3106], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3106], &n[3107], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[3107], &n[3108], &n[3093 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3108], &n[3109], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[3109], &n[3110], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3110], &n[3111], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3111], &n[3112], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3112], &n[3113], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]++
        w.Done()
        }
    }(&n[3113], &n[3114], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        if m[i] == 0 {
            j.Done()
        } else {
            w.Done()
        }
    
        }
    }(&n[3114], &n[3115], &n[3125 + 1])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3115], &n[3116], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3116], &n[3117], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3117], &n[3118], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3118], &n[3119], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3119], &n[3120], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3120], &n[3121], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3121], &n[3122], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3122], &n[3123], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3123], &n[3124], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i++
        w.Done()
        }
    }(&n[3124], &n[3125], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[3125], &n[3126], &n[3114 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3126], &n[3127], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3127], &n[3128], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3128], &n[3129], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        io.WriteByte(m[i])
        io.Flush()
        w.Done()
        }
    }(&n[3129], &n[3130], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3130], &n[3131], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        m[i]--
        w.Done()
        }
    }(&n[3131], &n[3132], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        j.Done()
    
        }
    }(&n[3132], &n[3133], &n[3011 + 0])
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3133], &n[3134], nil)
    go func(c *sync.WaitGroup, w *sync.WaitGroup, j *sync.WaitGroup){
        for {
            c.Wait()
            c.Add(1)

        i--
        w.Done()
        }
    }(&n[3134], &n[3135], nil)
    n[0].Done()
    n[3135].Wait()
    os.Exit(0)
}
