// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Mysql.outputs.ChannelTargetFilter;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ChannelTarget {
    /**
     * @return (Updatable) The username for the replication applier of the target MySQL DB System.
     * 
     */
    private @Nullable String applierUsername;
    /**
     * @return (Updatable) The case-insensitive name that identifies the replication channel. Channel names must follow the rules defined for [MySQL identifiers](https://dev.mysql.com/doc/refman/8.0/en/identifiers.html). The names of non-Deleted Channels must be unique for each DB System.
     * 
     */
    private @Nullable String channelName;
    /**
     * @return The OCID of the target DB System.
     * 
     */
    private String dbSystemId;
    /**
     * @return (Updatable) Specifies the amount of time, in seconds, that the channel waits before  applying a transaction received from the source.
     * 
     */
    private @Nullable Integer delayInSeconds;
    /**
     * @return (Updatable) Replication filter rules to be applied at the DB System Channel target.
     * 
     */
    private @Nullable List<ChannelTargetFilter> filters;
    /**
     * @return (Updatable) Specifies how a replication channel handles the creation and alteration of tables  that do not have a primary key. The default value is set to ALLOW.
     * 
     */
    private @Nullable String tablesWithoutPrimaryKeyHandling;
    /**
     * @return (Updatable) The specific target identifier.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private String targetType;

    private ChannelTarget() {}
    /**
     * @return (Updatable) The username for the replication applier of the target MySQL DB System.
     * 
     */
    public Optional<String> applierUsername() {
        return Optional.ofNullable(this.applierUsername);
    }
    /**
     * @return (Updatable) The case-insensitive name that identifies the replication channel. Channel names must follow the rules defined for [MySQL identifiers](https://dev.mysql.com/doc/refman/8.0/en/identifiers.html). The names of non-Deleted Channels must be unique for each DB System.
     * 
     */
    public Optional<String> channelName() {
        return Optional.ofNullable(this.channelName);
    }
    /**
     * @return The OCID of the target DB System.
     * 
     */
    public String dbSystemId() {
        return this.dbSystemId;
    }
    /**
     * @return (Updatable) Specifies the amount of time, in seconds, that the channel waits before  applying a transaction received from the source.
     * 
     */
    public Optional<Integer> delayInSeconds() {
        return Optional.ofNullable(this.delayInSeconds);
    }
    /**
     * @return (Updatable) Replication filter rules to be applied at the DB System Channel target.
     * 
     */
    public List<ChannelTargetFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return (Updatable) Specifies how a replication channel handles the creation and alteration of tables  that do not have a primary key. The default value is set to ALLOW.
     * 
     */
    public Optional<String> tablesWithoutPrimaryKeyHandling() {
        return Optional.ofNullable(this.tablesWithoutPrimaryKeyHandling);
    }
    /**
     * @return (Updatable) The specific target identifier.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public String targetType() {
        return this.targetType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ChannelTarget defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String applierUsername;
        private @Nullable String channelName;
        private String dbSystemId;
        private @Nullable Integer delayInSeconds;
        private @Nullable List<ChannelTargetFilter> filters;
        private @Nullable String tablesWithoutPrimaryKeyHandling;
        private String targetType;
        public Builder() {}
        public Builder(ChannelTarget defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applierUsername = defaults.applierUsername;
    	      this.channelName = defaults.channelName;
    	      this.dbSystemId = defaults.dbSystemId;
    	      this.delayInSeconds = defaults.delayInSeconds;
    	      this.filters = defaults.filters;
    	      this.tablesWithoutPrimaryKeyHandling = defaults.tablesWithoutPrimaryKeyHandling;
    	      this.targetType = defaults.targetType;
        }

        @CustomType.Setter
        public Builder applierUsername(@Nullable String applierUsername) {

            this.applierUsername = applierUsername;
            return this;
        }
        @CustomType.Setter
        public Builder channelName(@Nullable String channelName) {

            this.channelName = channelName;
            return this;
        }
        @CustomType.Setter
        public Builder dbSystemId(String dbSystemId) {
            if (dbSystemId == null) {
              throw new MissingRequiredPropertyException("ChannelTarget", "dbSystemId");
            }
            this.dbSystemId = dbSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder delayInSeconds(@Nullable Integer delayInSeconds) {

            this.delayInSeconds = delayInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<ChannelTargetFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(ChannelTargetFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder tablesWithoutPrimaryKeyHandling(@Nullable String tablesWithoutPrimaryKeyHandling) {

            this.tablesWithoutPrimaryKeyHandling = tablesWithoutPrimaryKeyHandling;
            return this;
        }
        @CustomType.Setter
        public Builder targetType(String targetType) {
            if (targetType == null) {
              throw new MissingRequiredPropertyException("ChannelTarget", "targetType");
            }
            this.targetType = targetType;
            return this;
        }
        public ChannelTarget build() {
            final var _resultValue = new ChannelTarget();
            _resultValue.applierUsername = applierUsername;
            _resultValue.channelName = channelName;
            _resultValue.dbSystemId = dbSystemId;
            _resultValue.delayInSeconds = delayInSeconds;
            _resultValue.filters = filters;
            _resultValue.tablesWithoutPrimaryKeyHandling = tablesWithoutPrimaryKeyHandling;
            _resultValue.targetType = targetType;
            return _resultValue;
        }
    }
}
