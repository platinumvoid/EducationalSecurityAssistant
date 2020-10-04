package org.secknight.secure_web_app.controllers.vulnerabilities;

import org.secknight.secure_web_app.database.SQLiteUserDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;

@Controller
@RequestMapping("/sql-interface")
public class SQL{

    /* Log all SQL errors in one Class */
    private static final Logger logger = LoggerFactory.getLogger(SQLiteUserDao.class);
    private static final Logger LOG = LoggerFactory.getLogger(SQL.class);
    private static final String template="redirect:/sql-interface";
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private DataSource dataSource;

    @ModelAttribute
    public void addAttributes(Model model) {
        model.addAttribute("secure", new Input());
        model.addAttribute("vulnerable", new Input());
    }

    @GetMapping
    public String home() {return "sql";}


    @PostMapping(consumes={MediaType.APPLICATION_FORM_URLENCODED_VALUE},params = "post_id1")
    public String secured(RedirectAttributes attributes, @ModelAttribute("secure") Input secure, BindingResult bindingResult)  {
        if (bindingResult.hasErrors())
            for(FieldError error : bindingResult.getFieldErrors())
                LOG.warn(error.getField()+" "+error.getDefaultMessage());
        else attributes.addFlashAttribute("output",getBooksSecure(secure.getInput()));
        return template;
    }

    @PostMapping(consumes={MediaType.APPLICATION_FORM_URLENCODED_VALUE},params = "post_id2")
    public String vulnerable(RedirectAttributes attributes,@ModelAttribute("vulnerable") Input vulnerable, BindingResult bindingResult) {
        if (bindingResult.hasErrors())
            for(FieldError error : bindingResult.getFieldErrors())
                LOG.warn(error.getField()+" "+error.getDefaultMessage());
        else attributes.addFlashAttribute("output",getBooksVulnerable(vulnerable.getInput()));
        return template;
    }

    /**
     * We use Prepared Statements (the query and the data are sent to the
     * database server separately) to protect from SQL Injections
     * and if any errors occur we log them and return an empty
     * string. In addition we specify the type and the name
     * of the column we want, so in case it does not match no
     * result will be returned.
     * @param book_name Book Title
     * @return SQL Output
     */
    public String getBooksSecure(String book_name) {
        try{
            return Objects.requireNonNull(jdbcTemplate.query(
                    "SELECT Title, Author, Year FROM Books WHERE Title = ? ",
                    preparedStatement -> preparedStatement.setString(1, book_name),
                    resultSet -> {
                        StringBuilder sb = new StringBuilder();
                        while (resultSet.next()) {
                            sb
                                    .append(resultSet.getString("Title")).append(" ")
                                    .append(resultSet.getString("Author")).append(" ")
                                    .append(resultSet.getString("Year"));

                            sb.append("<br>");
                        }
                        return sb;
                    }
            )).toString();
        }catch (DataAccessException | NullPointerException ex){
            logger.error("SQLiteUserDao: "+ex.getMessage());
            return "";
        }
    }

    /**
     * The biggest mistake here is that we are using
     * a dynamic sql query using "+input+" where we do
     * not even sanitize the input and blindly execute it.
     * An attacker can escape the current query using ';
     * and inject their own set of queries.
     *
     * Spring boot by default protects from the execution of
     * multiple queries in the same statement and either way is
     * not supported with SQLite. But if you are using any other
     * database and enable this feature, use jdbcTemplate.batchUpdate
     * to be safe.
     *
     * Also log any exceptions instead of printing them back to the
     * html page to prevent any sensitive Information Exposure.
     *
     * Finally do not select columns by their numbers and also specify
     * each column`s type to protect from the retrieval of arbitrary
     * results.
     *
     *
     * @param book_name Book Title
     * @return SQL Output
     */
    public String getBooksVulnerable(String book_name) {
        try{
            Connection con = DataSourceUtils.getConnection(dataSource);
            Statement stmt = con.createStatement();
            ResultSet resultSet = stmt.executeQuery
                    ("SELECT Title, Author, Year FROM Books WHERE Title= '"+book_name+"';");
            StringBuilder sb = new StringBuilder();
            while (resultSet.next()) {
                sb
                        .append(resultSet.getObject(1)).append(" ")
                        .append(resultSet.getObject(2)).append(" ")
                        .append(resultSet.getObject(3));

                sb.append("<br>");
            }
            return sb.toString();
        }catch (DataAccessException | SQLException ex){
            return ex.toString();
        }
    }
}

