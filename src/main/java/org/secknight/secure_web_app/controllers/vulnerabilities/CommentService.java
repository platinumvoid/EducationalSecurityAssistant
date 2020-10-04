package org.secknight.secure_web_app.controllers.vulnerabilities;

import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Used to demonstrate Stored XSS attacks to a
 * web site that uses a Comment Section
 */
@Service ("MyServices.CommentService")
public class CommentService {

   public static Map<Long, Comment> commentDB = new ConcurrentHashMap<>();

    public List<Comment> getList() {
        return new ArrayList<>(commentDB.values());
    }

    public void reset() {
        commentDB.clear();
    }

    public void add(Comment comment) {
        comment.setId(getNextId());
        commentDB.put(comment.getId(),comment);
    }

    private Long getNextId() {
        return commentDB.keySet()
                .stream()
                .mapToLong(value -> value)
                .max()
                .orElse(0) + 1;
    }
}
class Comment {
    private Long id;
    private String message;
    public void setId(Long id) {this.id = id;}
    public void setMessage(String message) {this.message = message;}
    public String getMessage() {return message;}
    public Long getId() {return id;}

    public Comment(String message){
        this.message=message;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Comment)) return false;
        Comment comment = (Comment) o;
        return Objects.equals(id, comment.id) &&
                Objects.equals(message, comment.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, message);
    }

    @Override
    public String toString() {
        return "Comment{" +
                "id=" + id +
                ", message='" + message + '\'' +
                '}';
    }
}