// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ObjectStorage.inputs.GetObjectsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetObjectsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetObjectsPlainArgs Empty = new GetObjectsPlainArgs();

    /**
     * The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     * 
     */
    @Import(name="bucket", required=true)
    private String bucket;

    /**
     * @return The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
     * 
     */
    public String bucket() {
        return this.bucket;
    }

    /**
     * When this parameter is set, only objects whose names do not contain the delimiter character (after an optionally specified prefix) are returned in the objects key of the response body. Scanned objects whose names contain the delimiter have the part of their name up to the first occurrence of the delimiter (including the optional prefix) returned as a set of prefixes. Note that only &#39;/&#39; is a supported delimiter character at this time.
     * 
     */
    @Import(name="delimiter")
    private @Nullable String delimiter;

    /**
     * @return When this parameter is set, only objects whose names do not contain the delimiter character (after an optionally specified prefix) are returned in the objects key of the response body. Scanned objects whose names contain the delimiter have the part of their name up to the first occurrence of the delimiter (including the optional prefix) returned as a set of prefixes. Note that only &#39;/&#39; is a supported delimiter character at this time.
     * 
     */
    public Optional<String> delimiter() {
        return Optional.ofNullable(this.delimiter);
    }

    /**
     * Object names returned by a list query must be strictly less than this parameter.
     * 
     */
    @Import(name="end")
    private @Nullable String end;

    /**
     * @return Object names returned by a list query must be strictly less than this parameter.
     * 
     */
    public Optional<String> end() {
        return Optional.ofNullable(this.end);
    }

    @Import(name="filters")
    private @Nullable List<GetObjectsFilter> filters;

    public Optional<List<GetObjectsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The Object Storage namespace used for the request.
     * 
     */
    @Import(name="namespace", required=true)
    private String namespace;

    /**
     * @return The Object Storage namespace used for the request.
     * 
     */
    public String namespace() {
        return this.namespace;
    }

    /**
     * The string to use for matching against the start of object names in a list query.
     * 
     */
    @Import(name="prefix")
    private @Nullable String prefix;

    /**
     * @return The string to use for matching against the start of object names in a list query.
     * 
     */
    public Optional<String> prefix() {
        return Optional.ofNullable(this.prefix);
    }

    /**
     * Object names returned by a list query must be greater or equal to this parameter.
     * 
     */
    @Import(name="start")
    private @Nullable String start;

    /**
     * @return Object names returned by a list query must be greater or equal to this parameter.
     * 
     */
    public Optional<String> start() {
        return Optional.ofNullable(this.start);
    }

    /**
     * Object names returned by a list query must be greater than this parameter.
     * 
     */
    @Import(name="startAfter")
    private @Nullable String startAfter;

    /**
     * @return Object names returned by a list query must be greater than this parameter.
     * 
     */
    public Optional<String> startAfter() {
        return Optional.ofNullable(this.startAfter);
    }

    private GetObjectsPlainArgs() {}

    private GetObjectsPlainArgs(GetObjectsPlainArgs $) {
        this.bucket = $.bucket;
        this.delimiter = $.delimiter;
        this.end = $.end;
        this.filters = $.filters;
        this.namespace = $.namespace;
        this.prefix = $.prefix;
        this.start = $.start;
        this.startAfter = $.startAfter;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetObjectsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetObjectsPlainArgs $;

        public Builder() {
            $ = new GetObjectsPlainArgs();
        }

        public Builder(GetObjectsPlainArgs defaults) {
            $ = new GetObjectsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bucket The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
         * 
         * @return builder
         * 
         */
        public Builder bucket(String bucket) {
            $.bucket = bucket;
            return this;
        }

        /**
         * @param delimiter When this parameter is set, only objects whose names do not contain the delimiter character (after an optionally specified prefix) are returned in the objects key of the response body. Scanned objects whose names contain the delimiter have the part of their name up to the first occurrence of the delimiter (including the optional prefix) returned as a set of prefixes. Note that only &#39;/&#39; is a supported delimiter character at this time.
         * 
         * @return builder
         * 
         */
        public Builder delimiter(@Nullable String delimiter) {
            $.delimiter = delimiter;
            return this;
        }

        /**
         * @param end Object names returned by a list query must be strictly less than this parameter.
         * 
         * @return builder
         * 
         */
        public Builder end(@Nullable String end) {
            $.end = end;
            return this;
        }

        public Builder filters(@Nullable List<GetObjectsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetObjectsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param namespace The Object Storage namespace used for the request.
         * 
         * @return builder
         * 
         */
        public Builder namespace(String namespace) {
            $.namespace = namespace;
            return this;
        }

        /**
         * @param prefix The string to use for matching against the start of object names in a list query.
         * 
         * @return builder
         * 
         */
        public Builder prefix(@Nullable String prefix) {
            $.prefix = prefix;
            return this;
        }

        /**
         * @param start Object names returned by a list query must be greater or equal to this parameter.
         * 
         * @return builder
         * 
         */
        public Builder start(@Nullable String start) {
            $.start = start;
            return this;
        }

        /**
         * @param startAfter Object names returned by a list query must be greater than this parameter.
         * 
         * @return builder
         * 
         */
        public Builder startAfter(@Nullable String startAfter) {
            $.startAfter = startAfter;
            return this;
        }

        public GetObjectsPlainArgs build() {
            $.bucket = Objects.requireNonNull($.bucket, "expected parameter 'bucket' to be non-null");
            $.namespace = Objects.requireNonNull($.namespace, "expected parameter 'namespace' to be non-null");
            return $;
        }
    }

}