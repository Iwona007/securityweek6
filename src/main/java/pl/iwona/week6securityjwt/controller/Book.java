package pl.iwona.week6securityjwt.controller;

import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.*;

@RestController
public class Book {

    private List<String> bookList;

    public Book() {
        this.bookList = new ArrayList<>();
        bookList.add("Boot 1");
        bookList.add("Book 2");
    }

    @GetMapping("/book")
    public List<String> getBookList() {
        System.out.println("available for users and admin");
        return bookList;
    }

    @PostMapping ("/add")
    public void setBookList(@RequestBody String book) {
        System.out.println("available for admin");
        this.bookList.add(book);
    }
}
