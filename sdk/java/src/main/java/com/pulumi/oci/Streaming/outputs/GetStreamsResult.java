// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Streaming.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Streaming.outputs.GetStreamsFilter;
import com.pulumi.oci.Streaming.outputs.GetStreamsStream;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetStreamsResult {
    /**
     * @return The OCID of the compartment that contains the stream.
     * 
     */
    private final @Nullable String compartmentId;
    private final @Nullable List<GetStreamsFilter> filters;
    /**
     * @return The OCID of the stream.
     * 
     */
    private final @Nullable String id;
    /**
     * @return The name of the stream. Avoid entering confidential information.  Example: `TelemetryEvents`
     * 
     */
    private final @Nullable String name;
    /**
     * @return The current state of the stream.
     * 
     */
    private final @Nullable String state;
    /**
     * @return The OCID of the stream pool that contains the stream.
     * 
     */
    private final @Nullable String streamPoolId;
    /**
     * @return The list of streams.
     * 
     */
    private final List<GetStreamsStream> streams;

    @CustomType.Constructor
    private GetStreamsResult(
        @CustomType.Parameter("compartmentId") @Nullable String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetStreamsFilter> filters,
        @CustomType.Parameter("id") @Nullable String id,
        @CustomType.Parameter("name") @Nullable String name,
        @CustomType.Parameter("state") @Nullable String state,
        @CustomType.Parameter("streamPoolId") @Nullable String streamPoolId,
        @CustomType.Parameter("streams") List<GetStreamsStream> streams) {
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.id = id;
        this.name = name;
        this.state = state;
        this.streamPoolId = streamPoolId;
        this.streams = streams;
    }

    /**
     * @return The OCID of the compartment that contains the stream.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public List<GetStreamsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The OCID of the stream.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The name of the stream. Avoid entering confidential information.  Example: `TelemetryEvents`
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The current state of the stream.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The OCID of the stream pool that contains the stream.
     * 
     */
    public Optional<String> streamPoolId() {
        return Optional.ofNullable(this.streamPoolId);
    }
    /**
     * @return The list of streams.
     * 
     */
    public List<GetStreamsStream> streams() {
        return this.streams;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetStreamsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable List<GetStreamsFilter> filters;
        private @Nullable String id;
        private @Nullable String name;
        private @Nullable String state;
        private @Nullable String streamPoolId;
        private List<GetStreamsStream> streams;

        public Builder() {
    	      // Empty
        }

        public Builder(GetStreamsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
    	      this.streamPoolId = defaults.streamPoolId;
    	      this.streams = defaults.streams;
        }

        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        public Builder filters(@Nullable List<GetStreamsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetStreamsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public Builder streamPoolId(@Nullable String streamPoolId) {
            this.streamPoolId = streamPoolId;
            return this;
        }
        public Builder streams(List<GetStreamsStream> streams) {
            this.streams = Objects.requireNonNull(streams);
            return this;
        }
        public Builder streams(GetStreamsStream... streams) {
            return streams(List.of(streams));
        }        public GetStreamsResult build() {
            return new GetStreamsResult(compartmentId, filters, id, name, state, streamPoolId, streams);
        }
    }
}
