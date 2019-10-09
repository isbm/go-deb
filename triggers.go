package deb

import (
	"bufio"
	"fmt"
	"strings"
)

type Trigger struct {
	directive string
	name      string
}

func NewTrigger() *Trigger {
	return new(Trigger)
}

func (t *Trigger) Directive() string {
	return t.directive
}

func (t *Trigger) Name() string {
	return t.name
}

type TriggerFile struct {
	triggers []Trigger
}

func NewTriggerFile() *TriggerFile {
	tf := new(TriggerFile)
	tf.triggers = make([]Trigger, 0)
	return tf
}

// Parse triggers file
func (tf *TriggerFile) parse(data []byte) error {
	scn := bufio.NewScanner(strings.NewReader(string(data)))
	for scn.Scan() {
		line := strings.TrimSpace(scn.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			dn := strings.SplitN(strings.Split(line, "#")[0], " ", 2) // Trim comments
			if len(dn) == 2 {
				t := NewTrigger()
				t.directive, t.name = dn[0], dn[1]
				tf.triggers = append(tf.triggers, *t)
			} else {
				return fmt.Errorf("Could not parse name and directive in '%v' line.", line)
			}
		}
	}
	return nil
}

// Triggers return known parsed triggers
func (tf TriggerFile) Triggers() []Trigger {
	return tf.triggers
}
