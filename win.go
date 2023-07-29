package main

import (
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"log"
	"math/rand"
)

const BuildVersion = "  Version:0.0.1\n  Author:cc"

// 主窗口大小
const MainWinMinWidth = 600
const MainWinMinHeight = 400

var searchTE *walk.LineEdit
var tableView *walk.TableView
var sbi *walk.StatusBarItem

type Item struct {
	index   int
	sip     string
	sport   uint16
	dip     string
	dport   uint16
	pktUp   uint32
	pktDown uint32
	seq     string
}

type DataModel struct {
	walk.TableModelBase
	sortColumn int
	sortOrder  walk.SortOrder
	items      []*Item
}

func (m *DataModel) RowCount() int {
	log.Println("row count")
	return len(m.items)
}

func NewDataModel() *DataModel {
	m := new(DataModel)
	m.ResetRows()
	return m
}

func (m *DataModel) ResetRows() {
	// Create some random data.
	m.items = make([]*Item, rand.Intn(10))

	for i := range m.items {
		m.items[i] = &Item{
			index: i,
		}
	}

	m.PublishRowsReset()
}

func (m *DataModel) Value(row, col int) interface{} {
	item := m.items[row]

	switch col {
	case 0:
		return item.index
	case 1:
		return item.sip
	case 2:
		return item.sport
	case 3:
		return item.dip
	case 4:
		return item.dport
	case 5:
		return item.pktUp
	case 6:
		return item.pktDown
	case 7:
		return item.seq
	}

	panic("unexpected col")
}

func main() {
	newwin := new(walk.MainWindow)
	datamodel := NewDataModel()
	MainWindow{
		Title:    "TCP序列号 分析器",
		AssignTo: &newwin,
		MinSize:  Size{MainWinMinWidth, MainWinMinHeight},
		Layout:   VBox{},
		//拖拽文件处理
		OnDropFiles: func(files []string) {
			if CheckPcap(files[0]) == false {
				walk.MsgBox(newwin, "错误", "非Pcap文件", walk.MsgBoxIconError)
			}
		},

		MenuItems: []MenuItem{
			Menu{
				Text: "文件",
				Items: []MenuItem{
					Action{
						Text: "退出",
						OnTriggered: func() {
							newwin.Close()
						},
					},
				},
			},
			Menu{
				Text: "帮助",
				Items: []MenuItem{
					Action{
						Text: "关于",
						OnTriggered: func() {
							walk.MsgBox(newwin, "关于", BuildVersion, walk.MsgBoxIconInformation)
						},
					},
				},
			},
		},

		Children: []Widget{
			GroupBox{
				Layout: HBox{},
				Children: []Widget{
					LineEdit{
						Name:      "filter",
						Alignment: AlignHNearVNear,
						MaxLength: 64,
						Row:       1,
						Column:    10,
						AssignTo:  &searchTE,
					},
					PushButton{
						Text: "过滤",
						OnClicked: func() {
							datamodel.ResetRows()
						},
					},
				},
			},

			TableView{
				AssignTo:      &tableView,
				Model:         datamodel,
				StretchFactor: 2,
				Columns: []TableViewColumn{
					TableViewColumn{
						DataMember: "No.",
						Alignment:  AlignCenter,
						Width:      128,
					},
					TableViewColumn{
						DataMember: "SrcIP",
						Alignment:  AlignCenter,
						Width:      128,
					},
					TableViewColumn{
						DataMember: "SrcPort",
						Alignment:  AlignCenter,
						Width:      128,
					},
					TableViewColumn{
						DataMember: "DstIP",
						Alignment:  AlignCenter,
						Width:      128,
					},
					TableViewColumn{
						DataMember: "DstPort",
						Alignment:  AlignCenter,
						Width:      128,
					},
					TableViewColumn{
						DataMember: "PKT_UP",
						Alignment:  AlignCenter,
						Width:      128,
					},
					TableViewColumn{
						DataMember: "PKT_DOWN",
						Alignment:  AlignCenter,
						Width:      128,
					},
					TableViewColumn{
						DataMember: "Seq",
						Alignment:  AlignCenter,
						Width:      100,
					},
				},
			},
		},
		StatusBarItems: []StatusBarItem{
			StatusBarItem{
				AssignTo: &sbi,
				Text:     "状态栏",
				Width:    MainWinMinWidth,
				OnClicked: func() {
					if sbi.Text() == "click" {
						sbi.SetText("again")
					} else {
						sbi.SetText("click")
					}
				},
			},
		},
	}.Create()

	newwin.Run()
}
