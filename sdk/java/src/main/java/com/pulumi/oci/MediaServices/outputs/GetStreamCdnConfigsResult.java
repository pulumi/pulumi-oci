// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MediaServices.outputs.GetStreamCdnConfigsFilter;
import com.pulumi.oci.MediaServices.outputs.GetStreamCdnConfigsStreamCdnConfigCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetStreamCdnConfigsResult {
    /**
     * @return The CDN Configuration identifier or display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return Distribution Channel Identifier.
     * 
     */
    private String distributionChannelId;
    private @Nullable List<GetStreamCdnConfigsFilter> filters;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private @Nullable String id;
    /**
     * @return The current state of the CDN Configuration.
     * 
     */
    private @Nullable String state;
    /**
     * @return The list of stream_cdn_config_collection.
     * 
     */
    private List<GetStreamCdnConfigsStreamCdnConfigCollection> streamCdnConfigCollections;

    private GetStreamCdnConfigsResult() {}
    /**
     * @return The CDN Configuration identifier or display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return Distribution Channel Identifier.
     * 
     */
    public String distributionChannelId() {
        return this.distributionChannelId;
    }
    public List<GetStreamCdnConfigsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The current state of the CDN Configuration.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The list of stream_cdn_config_collection.
     * 
     */
    public List<GetStreamCdnConfigsStreamCdnConfigCollection> streamCdnConfigCollections() {
        return this.streamCdnConfigCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetStreamCdnConfigsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String displayName;
        private String distributionChannelId;
        private @Nullable List<GetStreamCdnConfigsFilter> filters;
        private @Nullable String id;
        private @Nullable String state;
        private List<GetStreamCdnConfigsStreamCdnConfigCollection> streamCdnConfigCollections;
        public Builder() {}
        public Builder(GetStreamCdnConfigsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.distributionChannelId = defaults.distributionChannelId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.streamCdnConfigCollections = defaults.streamCdnConfigCollections;
        }

        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder distributionChannelId(String distributionChannelId) {
            if (distributionChannelId == null) {
              throw new MissingRequiredPropertyException("GetStreamCdnConfigsResult", "distributionChannelId");
            }
            this.distributionChannelId = distributionChannelId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetStreamCdnConfigsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetStreamCdnConfigsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder streamCdnConfigCollections(List<GetStreamCdnConfigsStreamCdnConfigCollection> streamCdnConfigCollections) {
            if (streamCdnConfigCollections == null) {
              throw new MissingRequiredPropertyException("GetStreamCdnConfigsResult", "streamCdnConfigCollections");
            }
            this.streamCdnConfigCollections = streamCdnConfigCollections;
            return this;
        }
        public Builder streamCdnConfigCollections(GetStreamCdnConfigsStreamCdnConfigCollection... streamCdnConfigCollections) {
            return streamCdnConfigCollections(List.of(streamCdnConfigCollections));
        }
        public GetStreamCdnConfigsResult build() {
            final var _resultValue = new GetStreamCdnConfigsResult();
            _resultValue.displayName = displayName;
            _resultValue.distributionChannelId = distributionChannelId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.state = state;
            _resultValue.streamCdnConfigCollections = streamCdnConfigCollections;
            return _resultValue;
        }
    }
}
