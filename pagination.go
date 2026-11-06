package signingflow

import (
	"context"
	"iter"
)

const maxPages = 100

// List is one page. All walks later pages and stops after 100 follow-up pages, a repeated token, or a false yield.
type List[T any] struct {
	Data          []T
	NextPageToken string
	load          func(context.Context, string) (List[T], error)
}

// All yields every item on this page and the pages after it.
func (l List[T]) All(ctx context.Context) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		page := l
		seen := map[string]struct{}{}
		pages := 0
		for {
			for _, item := range page.Data {
				if !yield(item, nil) {
					return
				}
			}
			token := page.NextPageToken
			if token == "" || page.load == nil {
				return
			}
			if _, ok := seen[token]; ok {
				return
			}
			pages++
			if pages > maxPages {
				var zero T
				yield(zero, invalid("Too many pages."))
				return
			}
			seen[token] = struct{}{}
			next, err := page.load(ctx, token)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			page = next
		}
	}
}

func nextToken(body map[string]any) string {
	if body == nil {
		return ""
	}
	if value := str(body["next_page_token"]); value != "" {
		return value
	}
	return str(body["nextPageToken"])
}

func listItems(body map[string]any, key string) []map[string]any {
	if body == nil {
		return nil
	}
	raw, ok := body[key].([]any)
	if !ok {
		return nil
	}
	items := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if record, ok := asMap(item); ok {
			items = append(items, record)
		}
	}
	return items
}

func pageSizeOf(value int) (int, error) {
	if value == 0 {
		return 10, nil
	}
	if value < 1 || value > 1000 {
		return 0, invalid("pageSize must be a whole number from 1 to 1000.")
	}
	return value, nil
}
