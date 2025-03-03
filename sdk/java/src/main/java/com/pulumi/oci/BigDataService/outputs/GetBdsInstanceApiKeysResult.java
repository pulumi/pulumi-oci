// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstanceApiKeysBdsApiKey;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstanceApiKeysFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetBdsInstanceApiKeysResult {
    /**
     * @return The list of bds_api_keys.
     * 
     */
    private List<GetBdsInstanceApiKeysBdsApiKey> bdsApiKeys;
    private String bdsInstanceId;
    private @Nullable String displayName;
    private @Nullable List<GetBdsInstanceApiKeysFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current status of the API key.
     * 
     */
    private @Nullable String state;
    /**
     * @return The user OCID for which this API key was created.
     * 
     */
    private @Nullable String userId;

    private GetBdsInstanceApiKeysResult() {}
    /**
     * @return The list of bds_api_keys.
     * 
     */
    public List<GetBdsInstanceApiKeysBdsApiKey> bdsApiKeys() {
        return this.bdsApiKeys;
    }
    public String bdsInstanceId() {
        return this.bdsInstanceId;
    }
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetBdsInstanceApiKeysFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The current status of the API key.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The user OCID for which this API key was created.
     * 
     */
    public Optional<String> userId() {
        return Optional.ofNullable(this.userId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBdsInstanceApiKeysResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetBdsInstanceApiKeysBdsApiKey> bdsApiKeys;
        private String bdsInstanceId;
        private @Nullable String displayName;
        private @Nullable List<GetBdsInstanceApiKeysFilter> filters;
        private String id;
        private @Nullable String state;
        private @Nullable String userId;
        public Builder() {}
        public Builder(GetBdsInstanceApiKeysResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bdsApiKeys = defaults.bdsApiKeys;
    	      this.bdsInstanceId = defaults.bdsInstanceId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.userId = defaults.userId;
        }

        @CustomType.Setter
        public Builder bdsApiKeys(List<GetBdsInstanceApiKeysBdsApiKey> bdsApiKeys) {
            if (bdsApiKeys == null) {
              throw new MissingRequiredPropertyException("GetBdsInstanceApiKeysResult", "bdsApiKeys");
            }
            this.bdsApiKeys = bdsApiKeys;
            return this;
        }
        public Builder bdsApiKeys(GetBdsInstanceApiKeysBdsApiKey... bdsApiKeys) {
            return bdsApiKeys(List.of(bdsApiKeys));
        }
        @CustomType.Setter
        public Builder bdsInstanceId(String bdsInstanceId) {
            if (bdsInstanceId == null) {
              throw new MissingRequiredPropertyException("GetBdsInstanceApiKeysResult", "bdsInstanceId");
            }
            this.bdsInstanceId = bdsInstanceId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetBdsInstanceApiKeysFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetBdsInstanceApiKeysFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetBdsInstanceApiKeysResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder userId(@Nullable String userId) {

            this.userId = userId;
            return this;
        }
        public GetBdsInstanceApiKeysResult build() {
            final var _resultValue = new GetBdsInstanceApiKeysResult();
            _resultValue.bdsApiKeys = bdsApiKeys;
            _resultValue.bdsInstanceId = bdsInstanceId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.state = state;
            _resultValue.userId = userId;
            return _resultValue;
        }
    }
}
