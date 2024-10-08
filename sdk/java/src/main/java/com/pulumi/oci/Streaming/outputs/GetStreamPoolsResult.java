// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Streaming.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Streaming.outputs.GetStreamPoolsFilter;
import com.pulumi.oci.Streaming.outputs.GetStreamPoolsStreamPool;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetStreamPoolsResult {
    /**
     * @return Compartment OCID that the pool belongs to.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetStreamPoolsFilter> filters;
    /**
     * @return The OCID of the stream pool.
     * 
     */
    private @Nullable String id;
    /**
     * @return The name of the stream pool.
     * 
     */
    private @Nullable String name;
    /**
     * @return The current state of the stream pool.
     * 
     */
    private @Nullable String state;
    /**
     * @return The list of stream_pools.
     * 
     */
    private List<GetStreamPoolsStreamPool> streamPools;

    private GetStreamPoolsResult() {}
    /**
     * @return Compartment OCID that the pool belongs to.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetStreamPoolsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The OCID of the stream pool.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The name of the stream pool.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The current state of the stream pool.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The list of stream_pools.
     * 
     */
    public List<GetStreamPoolsStreamPool> streamPools() {
        return this.streamPools;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetStreamPoolsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetStreamPoolsFilter> filters;
        private @Nullable String id;
        private @Nullable String name;
        private @Nullable String state;
        private List<GetStreamPoolsStreamPool> streamPools;
        public Builder() {}
        public Builder(GetStreamPoolsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
    	      this.streamPools = defaults.streamPools;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetStreamPoolsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetStreamPoolsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetStreamPoolsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder streamPools(List<GetStreamPoolsStreamPool> streamPools) {
            if (streamPools == null) {
              throw new MissingRequiredPropertyException("GetStreamPoolsResult", "streamPools");
            }
            this.streamPools = streamPools;
            return this;
        }
        public Builder streamPools(GetStreamPoolsStreamPool... streamPools) {
            return streamPools(List.of(streamPools));
        }
        public GetStreamPoolsResult build() {
            final var _resultValue = new GetStreamPoolsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.name = name;
            _resultValue.state = state;
            _resultValue.streamPools = streamPools;
            return _resultValue;
        }
    }
}
