// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Mysql.outputs.ChannelSourceAnonymousTransactionsHandling;
import com.pulumi.oci.Mysql.outputs.ChannelSourceSslCaCertificate;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ChannelSource {
    /**
     * @return (Updatable) Specifies how the replication channel handles replicated transactions without an identifier, enabling replication from a source that does not use transaction-id-based replication to a replica that does.
     * 
     */
    private @Nullable ChannelSourceAnonymousTransactionsHandling anonymousTransactionsHandling;
    /**
     * @return (Updatable) The network address of the MySQL instance.
     * 
     */
    private String hostname;
    /**
     * @return (Updatable) The password for the replication user. The password must be between 8 and 32 characters long, and must contain at least 1 numeric character, 1 lowercase character, 1 uppercase character, and 1 special (nonalphanumeric) character.
     * 
     */
    private String password;
    /**
     * @return (Updatable) The port the source MySQL instance listens on.
     * 
     */
    private @Nullable Integer port;
    /**
     * @return (Updatable) The specific source identifier.
     * 
     */
    private String sourceType;
    /**
     * @return (Updatable) The CA certificate of the server used for VERIFY_IDENTITY and VERIFY_CA ssl modes.
     * 
     */
    private @Nullable ChannelSourceSslCaCertificate sslCaCertificate;
    /**
     * @return (Updatable) The SSL mode of the Channel.
     * 
     */
    private String sslMode;
    /**
     * @return (Updatable) The name of the replication user on the source MySQL instance. The username has a maximum length of 96 characters. For more information, please see the [MySQL documentation](https://dev.mysql.com/doc/refman/8.0/en/change-master-to.html)
     * 
     */
    private String username;

    private ChannelSource() {}
    /**
     * @return (Updatable) Specifies how the replication channel handles replicated transactions without an identifier, enabling replication from a source that does not use transaction-id-based replication to a replica that does.
     * 
     */
    public Optional<ChannelSourceAnonymousTransactionsHandling> anonymousTransactionsHandling() {
        return Optional.ofNullable(this.anonymousTransactionsHandling);
    }
    /**
     * @return (Updatable) The network address of the MySQL instance.
     * 
     */
    public String hostname() {
        return this.hostname;
    }
    /**
     * @return (Updatable) The password for the replication user. The password must be between 8 and 32 characters long, and must contain at least 1 numeric character, 1 lowercase character, 1 uppercase character, and 1 special (nonalphanumeric) character.
     * 
     */
    public String password() {
        return this.password;
    }
    /**
     * @return (Updatable) The port the source MySQL instance listens on.
     * 
     */
    public Optional<Integer> port() {
        return Optional.ofNullable(this.port);
    }
    /**
     * @return (Updatable) The specific source identifier.
     * 
     */
    public String sourceType() {
        return this.sourceType;
    }
    /**
     * @return (Updatable) The CA certificate of the server used for VERIFY_IDENTITY and VERIFY_CA ssl modes.
     * 
     */
    public Optional<ChannelSourceSslCaCertificate> sslCaCertificate() {
        return Optional.ofNullable(this.sslCaCertificate);
    }
    /**
     * @return (Updatable) The SSL mode of the Channel.
     * 
     */
    public String sslMode() {
        return this.sslMode;
    }
    /**
     * @return (Updatable) The name of the replication user on the source MySQL instance. The username has a maximum length of 96 characters. For more information, please see the [MySQL documentation](https://dev.mysql.com/doc/refman/8.0/en/change-master-to.html)
     * 
     */
    public String username() {
        return this.username;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ChannelSource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable ChannelSourceAnonymousTransactionsHandling anonymousTransactionsHandling;
        private String hostname;
        private String password;
        private @Nullable Integer port;
        private String sourceType;
        private @Nullable ChannelSourceSslCaCertificate sslCaCertificate;
        private String sslMode;
        private String username;
        public Builder() {}
        public Builder(ChannelSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.anonymousTransactionsHandling = defaults.anonymousTransactionsHandling;
    	      this.hostname = defaults.hostname;
    	      this.password = defaults.password;
    	      this.port = defaults.port;
    	      this.sourceType = defaults.sourceType;
    	      this.sslCaCertificate = defaults.sslCaCertificate;
    	      this.sslMode = defaults.sslMode;
    	      this.username = defaults.username;
        }

        @CustomType.Setter
        public Builder anonymousTransactionsHandling(@Nullable ChannelSourceAnonymousTransactionsHandling anonymousTransactionsHandling) {

            this.anonymousTransactionsHandling = anonymousTransactionsHandling;
            return this;
        }
        @CustomType.Setter
        public Builder hostname(String hostname) {
            if (hostname == null) {
              throw new MissingRequiredPropertyException("ChannelSource", "hostname");
            }
            this.hostname = hostname;
            return this;
        }
        @CustomType.Setter
        public Builder password(String password) {
            if (password == null) {
              throw new MissingRequiredPropertyException("ChannelSource", "password");
            }
            this.password = password;
            return this;
        }
        @CustomType.Setter
        public Builder port(@Nullable Integer port) {

            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder sourceType(String sourceType) {
            if (sourceType == null) {
              throw new MissingRequiredPropertyException("ChannelSource", "sourceType");
            }
            this.sourceType = sourceType;
            return this;
        }
        @CustomType.Setter
        public Builder sslCaCertificate(@Nullable ChannelSourceSslCaCertificate sslCaCertificate) {

            this.sslCaCertificate = sslCaCertificate;
            return this;
        }
        @CustomType.Setter
        public Builder sslMode(String sslMode) {
            if (sslMode == null) {
              throw new MissingRequiredPropertyException("ChannelSource", "sslMode");
            }
            this.sslMode = sslMode;
            return this;
        }
        @CustomType.Setter
        public Builder username(String username) {
            if (username == null) {
              throw new MissingRequiredPropertyException("ChannelSource", "username");
            }
            this.username = username;
            return this;
        }
        public ChannelSource build() {
            final var _resultValue = new ChannelSource();
            _resultValue.anonymousTransactionsHandling = anonymousTransactionsHandling;
            _resultValue.hostname = hostname;
            _resultValue.password = password;
            _resultValue.port = port;
            _resultValue.sourceType = sourceType;
            _resultValue.sslCaCertificate = sslCaCertificate;
            _resultValue.sslMode = sslMode;
            _resultValue.username = username;
            return _resultValue;
        }
    }
}
