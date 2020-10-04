package org.secknight.secure_web_app.error_handling;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import org.springframework.core.Ordered;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.TypeMismatchException;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.NoHandlerFoundException;

/**
 * Translate Exception Messages thrown from everywhere in the application to
 * the appropriate error page with HTTP status code (RenderErrorController)
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class ControllerExceptionHandler {

	private static final Logger logger = LoggerFactory.getLogger(ControllerExceptionHandler.class);
	public static String error = "";

	@ResponseStatus(value = HttpStatus.CONFLICT, reason = "CONFLICT")
	@ExceptionHandler(DataIntegrityViolationException.class)
	public ModelAndView handleDataIntegrityViolationException(HttpServletRequest req,DataIntegrityViolationException ex) {
		logger.error("\nRequest: " + req.getRequestURL()+ "\nDataIntegrityViolationException: " +ex.getLocalizedMessage());
		return new ModelAndView("error");
	}
	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "BAD REQUEST")
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ModelAndView handleMethodArgumentNotValid(HttpServletRequest req, MethodArgumentNotValidException ex) {
		logger.error(getFieldErrorOutput(ex.getBindingResult(), ex, req));
		return new ModelAndView("error");
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "BAD REQUEST")
	@ExceptionHandler(BindException.class)
	public ModelAndView handleBindException(HttpServletRequest req, BindException ex) {
		logger.error(getFieldErrorOutput(ex.getBindingResult(), ex, req));
		return new ModelAndView("error");
	}

	private String getFieldErrorOutput(BindingResult bindingResult, Exception ex, HttpServletRequest req) {
		StringBuilder output= new StringBuilder("\nRequest: " + req.getRequestURL() +
				"\n"+ex.getClass().getSimpleName()+": " + ex.getLocalizedMessage() +
				"\nField Errors: ");
		List<String> errors = new ArrayList<>();
		for (final FieldError field_error : bindingResult.getFieldErrors()) {
			errors.add(field_error.getField() + ": " + field_error.getDefaultMessage());
		}
		for (final ObjectError object_error : bindingResult.getGlobalErrors()) {
			errors.add(object_error.getObjectName() + ": " + object_error.getDefaultMessage());
		}

		for (String error : errors){
			output.append("\n").append(error);
		}
		return output.toString();
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "BAD REQUEST")
	@ExceptionHandler(TypeMismatchException.class)
	public ModelAndView handleTypeMismatch(HttpServletRequest req, TypeMismatchException ex) {
		logger.error("\nRequest: " + req.getRequestURL()+
				"\nTypeMismatchException: " +ex.getValue() + " value for " + ex.getPropertyName() + " should be of type " + ex.getRequiredType());
		return new ModelAndView("error");
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "BAD REQUEST")
	@ExceptionHandler(MissingServletRequestPartException.class)
	public ModelAndView handleMissingServletRequestPart(HttpServletRequest req, MissingServletRequestPartException ex) {
		logger.error("Request: " + req.getRequestURL() +
				"\nMissingServletRequestPartException: " + ex.getRequestPartName() + " part is missing");
		return new ModelAndView("error");
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "BAD REQUEST")
	@ExceptionHandler(MissingServletRequestParameterException.class)
	public ModelAndView handleMissingServletRequestParameter(HttpServletRequest req, MissingServletRequestParameterException ex) {
		logger.error("Request: " + req.getRequestURL() +
				"\nMissingServletRequestParameterException: " + ex.getParameterName() + " parameter is missing");
		return new ModelAndView("error");
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "BAD REQUEST")
	@ExceptionHandler(MethodArgumentTypeMismatchException.class)
	public ModelAndView handleMethodArgumentTypeMismatch(HttpServletRequest req, MethodArgumentTypeMismatchException ex) {
		logger.error("Request: " + req.getRequestURL() +
				"\nMethodArgumentTypeMismatchException:  " + ex.getName() + " should be of type " + Objects.requireNonNull(ex.getRequiredType()).getName());
		return new ModelAndView("error");
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "BAD REQUEST")
	@ExceptionHandler(ConstraintViolationException.class)
	public ModelAndView handleConstraintViolation(HttpServletRequest req, ConstraintViolationException ex) {
		List<String> errors = new ArrayList<>();
		final StringBuilder builder = new StringBuilder();
		for (final ConstraintViolation<?> violation : ex.getConstraintViolations()) {
			errors.add(violation.getRootBeanClass().getName() + " " + violation.getPropertyPath() + ": "+ violation.getMessage());
		}
		for(String line : errors){
			builder.append(line).append(", ");
		}
		logger.error("Request: " + req.getRequestURL() + " raised " + builder.toString());
		return new ModelAndView("error");
	}

	@ResponseStatus(value = HttpStatus.FORBIDDEN, reason = "ACCESS IS DENIED")
	@ExceptionHandler({ AccessDeniedException.class })
	public String forbidden() { return "error"; }

	@ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "PAGE NOT FOUND")
	@ExceptionHandler(NoHandlerFoundException.class)
	public String handleNoHandlerFoundException() { return "error"; }

	@ResponseStatus(value = HttpStatus.METHOD_NOT_ALLOWED, reason = "METHOD NOT ALLOWED")
	@ExceptionHandler(HttpRequestMethodNotSupportedException.class)
	public ModelAndView handleHttpRequestMethodNotSupported(HttpServletRequest req, HttpRequestMethodNotSupportedException ex) {
		final StringBuilder builder = new StringBuilder();
		builder.append(ex.getMethod());
		builder.append(" method is not supported for this request. Supported methods are ");
		Objects.requireNonNull(ex.getSupportedHttpMethods()).forEach(t -> builder.append(t).append(" "));
		logger.error("Request: " + req.getRequestURL() +
				"\nHttpRequestMethodNotSupportedException" + builder.toString());
		return new ModelAndView("error");
	}

	@ResponseStatus(value = HttpStatus.UNSUPPORTED_MEDIA_TYPE, reason = "METHOD NOT ALLOWED")
	@ExceptionHandler(HttpMediaTypeNotSupportedException.class)
	public ModelAndView handleHttpMediaTypeNotSupported(HttpServletRequest req, HttpMediaTypeNotSupportedException ex) {
		final StringBuilder builder = new StringBuilder();
		builder.append(ex.getContentType());
		builder.append(" media type is not supported. Supported media types are ");
		ex.getSupportedMediaTypes().forEach(t -> builder.append(t).append(" "));
		logger.error("Request: " + req.getRequestURL() +
				"\nHttpMediaTypeNotSupportedException" + builder.toString());
		return new ModelAndView("error");
	}

	@ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "File not Found")
	@ExceptionHandler(StorageFileNotFoundException.class)
	public ModelAndView handleStorageFileNotFound() {
		return new ModelAndView("error");
	}

	@ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR, reason = "Error Creating Storage")
	@ExceptionHandler(StorageException.class)
	public ModelAndView handleStorageException(StorageException exc) {
		logger.error("StorageException: " +exc.getMessage());
		return new ModelAndView("error");
	}

	// Unknown Exception
	@ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "BAD REQUEST")
	@ExceptionHandler(Exception.class)
	public ModelAndView handleAll(HttpServletRequest req, Exception ex) {
		logger.error("Request: " + req.getRequestURL() + " raised " + ex);
		return new ModelAndView("error");
	}
}