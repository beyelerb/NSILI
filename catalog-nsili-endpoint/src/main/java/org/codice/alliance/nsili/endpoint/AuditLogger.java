/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.alliance.nsili.endpoint;

import ddf.security.SecurityConstants;
import ddf.security.SubjectOperations;
import ddf.security.service.impl.SubjectUtils;
import java.security.AccessController;
import java.util.Set;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.karaf.jaas.boot.principal.UserPrincipal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.util.Supplier;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

/**
 * This AuditLogger is specific to the NSILI Endpoint - by design, it runs without any security or
 * knowledge of the calling user. As such, this auditor has been streamlined to assume the guest
 * user or no user in order to generate logs for the audit.
 */
public class AuditLogger implements ddf.security.audit.SecurityLogger {
  private static final Logger LOGGER = LogManager.getLogger(SecurityConstants.SECURITY_LOGGER);

  private static final String NO_USER = "UNKNOWN";

  private static final boolean REQUIRE_AUDIT_ENCODING =
      Boolean.parseBoolean(
          System.getProperty("org.codice.ddf.platform.requireAuditEncoding", "false"));

  private static final String SUBJECT = "Subject: ";

  private static final String EXTRA_ATTRIBUTES_PROP = "security.logger.extra_attributes";

  private static final SubjectOperations subjectOperations = new SubjectUtils();

  public AuditLogger() {}

  private String getUser(Subject subject) {
    try {
      if (subject == null) {
        subject = ThreadContext.getSubject();
      }
      if (subject == null) {
        javax.security.auth.Subject javaSubject =
            javax.security.auth.Subject.getSubject(AccessController.getContext());
        if (javaSubject != null) {
          Set<UserPrincipal> userPrincipal = javaSubject.getPrincipals(UserPrincipal.class);
          if (userPrincipal != null && !userPrincipal.isEmpty()) {
            return userPrincipal.toArray(new UserPrincipal[1])[0].getName();
          }
        }
      } else {
        return NO_USER;
      }
    } catch (Exception e) {
      // ignore and return NO_USER
    }
    return NO_USER;
  }

  private void requestIpAndPortAndUserMessage(StringBuilder messageBuilder) {
    requestIpAndPortAndUserMessage(null, messageBuilder);
  }

  private void requestIpAndPortAndUserMessage(Subject subject, StringBuilder messageBuilder) {
    String user = getUser(subject);
    messageBuilder.append(SUBJECT).append(user);
    // appendConditionalAttributes(subject, messageBuilder);
    messageBuilder.append(" ");
  }

  /**
   * Ensure that logs cannot be forged.
   *
   * @param message
   * @return clean message
   */
  private String cleanAndEncode(String message) {
    String clean = message.replace('\n', '_').replace('\r', '_');
    if (REQUIRE_AUDIT_ENCODING) {
      clean = StringEscapeUtils.escapeHtml(clean);
    }
    return clean;
  }

  /**
   * Logs a message object with the {@link org.apache.logging.log4j.Level#INFO INFO} level.
   *
   * @param message the message string to log.
   * @param subject the user subject to log
   */
  @Override
  public void audit(String message, Subject subject) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(subject, messageBuilder);
    LOGGER.info(messageBuilder.append(cleanAndEncode(message)).toString());
  }

  /**
   * Logs a message object with the {@link org.apache.logging.log4j.Level#INFO INFO} level.
   *
   * @param message the message string to log.
   */
  @Override
  public void audit(String message) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(messageBuilder);
    LOGGER.info(messageBuilder.append(cleanAndEncode(message)).toString());
  }

  /**
   * Logs a message with parameters at the {@link org.apache.logging.log4j.Level#INFO INFO} level.
   *
   * @param message the message to log; the format depends on the message factory.
   * @param subject the user subject to log
   * @param params parameters to the message.
   */
  @Override
  public void audit(String message, Subject subject, Object... params) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(subject, messageBuilder);
    LOGGER.info(messageBuilder.append(cleanAndEncode(message)).toString(), params);
  }

  /**
   * Logs a message with parameters at the {@link org.apache.logging.log4j.Level#INFO INFO} level.
   *
   * @param message the message to log; the format depends on the message factory.
   * @param params parameters to the message.
   */
  @Override
  public void audit(String message, Object... params) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(messageBuilder);
    LOGGER.info(messageBuilder.append(cleanAndEncode(message)).toString(), params);
  }

  /**
   * Logs a message with parameters which are only to be constructed if the logging level is the
   * {@link org.apache.logging.log4j.Level#INFO INFO} level.
   *
   * @param message the message to log; the format depends on the message factory.
   * @param subject the user subject to log
   * @param paramSuppliers An array of functions, which when called, produce the desired log message
   *     parameters.
   */
  @Override
  public void audit(String message, Subject subject, Supplier... paramSuppliers) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(subject, messageBuilder);
    LOGGER.info(messageBuilder.append(cleanAndEncode(message)).toString(), paramSuppliers);
  }

  /**
   * Logs a message with parameters which are only to be constructed if the logging level is the
   * {@link org.apache.logging.log4j.Level#INFO INFO} level.
   *
   * @param message the message to log; the format depends on the message factory.
   * @param paramSuppliers An array of functions, which when called, produce the desired log message
   *     parameters.
   */
  @Override
  public void audit(String message, Supplier... paramSuppliers) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(messageBuilder);
    LOGGER.info(messageBuilder.append(cleanAndEncode(message)).toString(), paramSuppliers);
  }

  /**
   * Logs a message at the {@link org.apache.logging.log4j.Level#INFO INFO} level including the
   * stack trace of the {@link Throwable} <code>t</code> passed as parameter.
   *
   * @param message the message object to log.
   * @param subject the user subject to log
   * @param t the exception to log, including its stack trace.
   */
  @Override
  public void audit(String message, Subject subject, Throwable t) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(subject, messageBuilder);
    LOGGER.info(messageBuilder.append(cleanAndEncode(message)).toString(), t);
  }

  /**
   * Logs a message at the {@link org.apache.logging.log4j.Level#INFO INFO} level including the
   * stack trace of the {@link Throwable} <code>t</code> passed as parameter.
   *
   * @param message the message object to log.
   * @param t the exception to log, including its stack trace.
   */
  @Override
  public void audit(String message, Throwable t) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(messageBuilder);
    LOGGER.info(messageBuilder.append(cleanAndEncode(message)).toString(), t);
  }

  /**
   * Logs a message object with the {@link org.apache.logging.log4j.Level#WARN WARN} level.
   *
   * @param message the message string to log.
   * @param subject the user subject to log
   */
  @Override
  public void auditWarn(String message, Subject subject) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(subject, messageBuilder);
    LOGGER.warn(messageBuilder.append(cleanAndEncode(message)).toString());
  }

  /**
   * Logs a message object with the {@link org.apache.logging.log4j.Level#WARN WARN} level.
   *
   * @param message the message string to log.
   */
  @Override
  public void auditWarn(String message) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(messageBuilder);
    LOGGER.warn(messageBuilder.append(cleanAndEncode(message)).toString());
  }

  /**
   * Logs a message with parameters at the {@link org.apache.logging.log4j.Level#WARN WARN} level.
   *
   * @param message the message to log; the format depends on the message factory.
   * @param subject the user subject to log
   * @param params parameters to the message.
   */
  @Override
  public void auditWarn(String message, Subject subject, Object... params) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(subject, messageBuilder);
    LOGGER.warn(messageBuilder.append(cleanAndEncode(message)).toString(), params);
  }

  /**
   * Logs a message with parameters at the {@link org.apache.logging.log4j.Level#WARN WARN} level.
   *
   * @param message the message to log; the format depends on the message factory.
   * @param params parameters to the message.
   */
  @Override
  public void auditWarn(String message, Object... params) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(messageBuilder);
    LOGGER.warn(messageBuilder.append(cleanAndEncode(message)).toString(), params);
  }

  /**
   * Logs a message with parameters which are only to be constructed if the logging level is the
   * {@link org.apache.logging.log4j.Level#WARN WARN} level.
   *
   * @param message the message to log; the format depends on the message factory.
   * @param subject the user subject to log
   * @param paramSuppliers An array of functions, which when called, produce the desired log message
   *     parameters.
   */
  @Override
  public void auditWarn(String message, Subject subject, Supplier... paramSuppliers) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(subject, messageBuilder);
    LOGGER.warn(messageBuilder.append(cleanAndEncode(message)).toString(), paramSuppliers);
  }

  /**
   * Logs a message with parameters which are only to be constructed if the logging level is the
   * {@link org.apache.logging.log4j.Level#WARN WARN} level.
   *
   * @param message the message to log; the format depends on the message factory.
   * @param paramSuppliers An array of functions, which when called, produce the desired log message
   *     parameters.
   */
  @Override
  public void auditWarn(String message, Supplier... paramSuppliers) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(messageBuilder);
    LOGGER.warn(messageBuilder.append(cleanAndEncode(message)).toString(), paramSuppliers);
  }

  /**
   * Logs a message at the {@link org.apache.logging.log4j.Level#WARN WARN} level including the
   * stack trace of the {@link Throwable} <code>t</code> passed as parameter.
   *
   * @param message the message object to log.
   * @param subject the user subject to log
   * @param t the exception to log, including its stack trace.
   */
  @Override
  public void auditWarn(String message, Subject subject, Throwable t) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(subject, messageBuilder);
    LOGGER.warn(messageBuilder.append(cleanAndEncode(message)).toString(), t);
  }

  /**
   * Logs a message at the {@link org.apache.logging.log4j.Level#WARN WARN} level including the
   * stack trace of the {@link Throwable} <code>t</code> passed as parameter.
   *
   * @param message the message object to log.
   * @param t the exception to log, including its stack trace.
   */
  @Override
  public void auditWarn(String message, Throwable t) {
    StringBuilder messageBuilder = new StringBuilder();
    requestIpAndPortAndUserMessage(messageBuilder);
    LOGGER.warn(messageBuilder.append(cleanAndEncode(message)).toString(), t);
  }
}
