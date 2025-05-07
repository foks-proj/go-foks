// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle        = lipgloss.NewStyle().MarginLeft(2)
	h1Style           = lipgloss.NewStyle().Bold(true).BorderStyle(lipgloss.DoubleBorder()).Padding(1)
	h2Style           = lipgloss.NewStyle().Bold(true).Padding(1)
	historyStyle      = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).Padding(0, 1)
	italicStyle       = lipgloss.NewStyle().Italic(true)
	BoldStyle         = lipgloss.NewStyle().Bold(true)
	helpStyle         = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)
	ErrorStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
	WarningStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500"))
	BoldErrorStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF0000"))
	HappyStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
	itemStyle         = lipgloss.NewStyle().PaddingLeft(5)
	textInputStyle    = lipgloss.NewStyle().PaddingLeft(4)
	selectedItemStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("170"))
	paginationStyle   = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	spinnerStyle      = spinner.Dot
)

func styleList(l *list.Model) {
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = titleStyle
	l.Styles.PaginationStyle = paginationStyle
	l.Styles.HelpStyle = helpStyle
}

const (
	defaultWidth = 80
	listHeight   = 13
)
