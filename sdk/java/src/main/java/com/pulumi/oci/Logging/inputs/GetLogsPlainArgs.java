// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Logging.inputs.GetLogsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetLogsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetLogsPlainArgs Empty = new GetLogsPlainArgs();

    /**
     * Resource name
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return Resource name
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetLogsFilter> filters;

    public Optional<List<GetLogsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * OCID of a log group to work with.
     * 
     */
    @Import(name="logGroupId", required=true)
    private String logGroupId;

    /**
     * @return OCID of a log group to work with.
     * 
     */
    public String logGroupId() {
        return this.logGroupId;
    }

    /**
     * The logType that the log object is for, whether custom or service.
     * 
     */
    @Import(name="logType")
    private @Nullable String logType;

    /**
     * @return The logType that the log object is for, whether custom or service.
     * 
     */
    public Optional<String> logType() {
        return Optional.ofNullable(this.logType);
    }

    /**
     * Log object resource.
     * 
     */
    @Import(name="sourceResource")
    private @Nullable String sourceResource;

    /**
     * @return Log object resource.
     * 
     */
    public Optional<String> sourceResource() {
        return Optional.ofNullable(this.sourceResource);
    }

    /**
     * Service that created the log object.
     * 
     */
    @Import(name="sourceService")
    private @Nullable String sourceService;

    /**
     * @return Service that created the log object.
     * 
     */
    public Optional<String> sourceService() {
        return Optional.ofNullable(this.sourceService);
    }

    /**
     * Lifecycle state of the log object
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return Lifecycle state of the log object
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetLogsPlainArgs() {}

    private GetLogsPlainArgs(GetLogsPlainArgs $) {
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.logGroupId = $.logGroupId;
        this.logType = $.logType;
        this.sourceResource = $.sourceResource;
        this.sourceService = $.sourceService;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetLogsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetLogsPlainArgs $;

        public Builder() {
            $ = new GetLogsPlainArgs();
        }

        public Builder(GetLogsPlainArgs defaults) {
            $ = new GetLogsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName Resource name
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetLogsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetLogsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param logGroupId OCID of a log group to work with.
         * 
         * @return builder
         * 
         */
        public Builder logGroupId(String logGroupId) {
            $.logGroupId = logGroupId;
            return this;
        }

        /**
         * @param logType The logType that the log object is for, whether custom or service.
         * 
         * @return builder
         * 
         */
        public Builder logType(@Nullable String logType) {
            $.logType = logType;
            return this;
        }

        /**
         * @param sourceResource Log object resource.
         * 
         * @return builder
         * 
         */
        public Builder sourceResource(@Nullable String sourceResource) {
            $.sourceResource = sourceResource;
            return this;
        }

        /**
         * @param sourceService Service that created the log object.
         * 
         * @return builder
         * 
         */
        public Builder sourceService(@Nullable String sourceService) {
            $.sourceService = sourceService;
            return this;
        }

        /**
         * @param state Lifecycle state of the log object
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetLogsPlainArgs build() {
            $.logGroupId = Objects.requireNonNull($.logGroupId, "expected parameter 'logGroupId' to be non-null");
            return $;
        }
    }

}