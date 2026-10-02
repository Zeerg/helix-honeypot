package ai

import (
	"encoding/json"
	"strings"
	"time"
)

func ndjson(values ...object) result {
	out := result{code: 200, contentType: "application/x-ndjson"}
	for _, value := range values {
		data, _ := json.Marshal(value)
		out.frames = append(out.frames, append(data, '\n'))
	}
	return out
}
func sse(events ...object) result {
	out := result{code: 200, contentType: "text/event-stream"}
	for _, event := range events {
		data, _ := json.Marshal(event)
		prefix := ""
		if kind, ok := event["type"].(string); ok {
			prefix = "event: " + kind + "\n"
		}
		out.frames = append(out.frames, []byte(prefix+"data: "+string(data)+"\n\n"))
	}
	return out
}
func ollamaReply(path, name string, stream bool, textValue string, tokens int) result {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	makePart := func(text string, done bool) object {
		part := object{"model": name, "created_at": now, "done": done}
		if path == "/api/chat" {
			part["message"] = object{"role": "assistant", "content": text}
		} else {
			part["response"] = text
		}
		if done {
			part["done_reason"] = "stop"
			part["total_duration"] = 1000000
			part["load_duration"] = 0
			part["prompt_eval_count"] = 1
			part["eval_count"] = tokens
			part["eval_duration"] = 1000000
		}
		return part
	}
	if stream {
		return ndjson(makePart(textValue, false), makePart("", true))
	}
	return jsonResult(200, makePart(textValue, true))
}
func chatReply(name, id string, stream bool, req object, textValue string, tokens int) result {
	now := time.Now().Unix()
	usage := object{"prompt_tokens": 1, "completion_tokens": tokens, "total_tokens": tokens + 1}
	if !stream {
		return jsonResult(200, object{"id": id, "object": "chat.completion", "created": now, "model": name, "choices": []object{{"index": 0, "message": object{"role": "assistant", "content": textValue}, "finish_reason": "stop", "logprobs": nil}}, "usage": usage})
	}
	chunk := func(delta object, finish any) object {
		return object{"id": id, "object": "chat.completion.chunk", "created": now, "model": name, "choices": []object{{"index": 0, "delta": delta, "finish_reason": finish, "logprobs": nil}}}
	}
	out := sse(chunk(object{"role": "assistant", "content": ""}, nil), chunk(object{"content": textValue}, nil), chunk(object{}, "stop"))
	if opts, ok := req["stream_options"].(map[string]any); ok && opts["include_usage"] == true {
		frame := sse(object{"id": id, "object": "chat.completion.chunk", "created": now, "model": name, "choices": []object{}, "usage": usage})
		out.frames = append(out.frames, frame.frames...)
	}
	out.frames = append(out.frames, []byte("data: [DONE]\n\n"))
	return out
}
func anthropicReply(name, id string, stream bool, textValue string, tokens int) result {
	message := func(content []object, reason any, output int) object {
		return object{"id": id, "type": "message", "role": "assistant", "model": name, "content": content, "stop_reason": reason, "stop_sequence": nil, "usage": object{"input_tokens": 1, "output_tokens": output}}
	}
	if !stream {
		return jsonResult(200, message([]object{{"type": "text", "text": textValue}}, "end_turn", tokens))
	}
	return sse(
		object{"type": "message_start", "message": message([]object{}, nil, 0)},
		object{"type": "content_block_start", "index": 0, "content_block": object{"type": "text", "text": ""}},
		object{"type": "content_block_delta", "index": 0, "delta": object{"type": "text_delta", "text": textValue}},
		object{"type": "content_block_stop", "index": 0},
		object{"type": "message_delta", "delta": object{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": object{"output_tokens": tokens}},
		object{"type": "message_stop"},
	)
}
func responsesReply(name, id string, stream bool, textValue string, tokens int) result {
	itemID := "msg_" + id
	text := object{"type": "output_text", "text": textValue, "annotations": []any{}, "logprobs": []any{}}
	item := object{"id": itemID, "type": "message", "status": "completed", "role": "assistant", "content": []object{text}}
	response := func(status string, output []object) object {
		return object{"id": id, "object": "response", "created_at": time.Now().Unix(), "status": status, "model": name, "output": output, "error": nil, "incomplete_details": nil, "parallel_tool_calls": false, "tools": []any{}, "tool_choice": "none", "store": false, "usage": object{"input_tokens": 1, "output_tokens": tokens, "total_tokens": tokens + 1, "input_tokens_details": object{"cached_tokens": 0}, "output_tokens_details": object{"reasoning_tokens": 0}}}
	}
	completed := response("completed", []object{item})
	if !stream {
		return jsonResult(200, completed)
	}
	emptyPart := object{"type": "output_text", "text": "", "annotations": []any{}, "logprobs": []any{}}
	events := []object{
		{"type": "response.created", "response": response("in_progress", []object{})},
		{"type": "response.in_progress", "response": response("in_progress", []object{})},
		{"type": "response.output_item.added", "output_index": 0, "item": object{"id": itemID, "type": "message", "status": "in_progress", "role": "assistant", "content": []object{}}},
		{"type": "response.content_part.added", "item_id": itemID, "output_index": 0, "content_index": 0, "part": emptyPart},
		{"type": "response.output_text.delta", "item_id": itemID, "output_index": 0, "content_index": 0, "delta": textValue, "logprobs": []any{}},
		{"type": "response.output_text.done", "item_id": itemID, "output_index": 0, "content_index": 0, "text": textValue, "logprobs": []any{}},
		{"type": "response.content_part.done", "item_id": itemID, "output_index": 0, "content_index": 0, "part": text},
		{"type": "response.output_item.done", "output_index": 0, "item": item},
		{"type": "response.completed", "response": completed},
	}
	for i, event := range events {
		event["sequence_number"] = i
	}
	return sse(events...)
}

// Counts are synthetic, not provider tokenization. Each fixed chunk consumes
// one synthetic output token, so requested positive budgets also bound text.
func generatedText(req object) (string, int, bool) {
	chunks := []string{"Hello", "!", " How", " can", " I", " help", " you", " today", "?"}
	budget := len(chunks)
	for _, key := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens"} {
		if raw, exists := req[key]; exists {
			n, ok := raw.(float64)
			if !ok || n < 1 || n > 32768 || n != float64(int(n)) {
				return "", 0, false
			}
			if int(n) < budget {
				budget = int(n)
			}
		}
	}
	if opts, ok := req["options"].(map[string]any); ok {
		if raw, exists := opts["num_predict"]; exists {
			n, ok := raw.(float64)
			if !ok || n > 32768 || n != float64(int(n)) || n == 0 || n < -2 {
				return "", 0, false
			}
			if n > 0 && int(n) < budget {
				budget = int(n)
			}
		}
	}
	return strings.Join(chunks[:budget], ""), budget, true
}
