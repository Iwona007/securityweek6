package pl.iwona.week6securityjwt.controller;

import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/book")
public class Book {

    private List<String> bookList;

    public Book() {
        this.bookList = new ArrayList<>();
        bookList.add("Boot 1");
        bookList.add("Book 2");
    }

    @GetMapping
    public List<String> getBookList() {
        return bookList;
    }

    @PostMapping
    public void setBookList(@RequestBody String book) {
        this.bookList.add(book);
    }
}
