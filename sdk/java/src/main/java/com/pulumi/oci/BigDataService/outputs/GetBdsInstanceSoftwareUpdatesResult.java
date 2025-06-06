// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstanceSoftwareUpdatesFilter;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstanceSoftwareUpdatesSoftwareUpdateCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetBdsInstanceSoftwareUpdatesResult {
    private String bdsInstanceId;
    private @Nullable List<GetBdsInstanceSoftwareUpdatesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of software_update_collection.
     * 
     */
    private List<GetBdsInstanceSoftwareUpdatesSoftwareUpdateCollection> softwareUpdateCollections;

    private GetBdsInstanceSoftwareUpdatesResult() {}
    public String bdsInstanceId() {
        return this.bdsInstanceId;
    }
    public List<GetBdsInstanceSoftwareUpdatesFilter> filters() {
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
     * @return The list of software_update_collection.
     * 
     */
    public List<GetBdsInstanceSoftwareUpdatesSoftwareUpdateCollection> softwareUpdateCollections() {
        return this.softwareUpdateCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBdsInstanceSoftwareUpdatesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bdsInstanceId;
        private @Nullable List<GetBdsInstanceSoftwareUpdatesFilter> filters;
        private String id;
        private List<GetBdsInstanceSoftwareUpdatesSoftwareUpdateCollection> softwareUpdateCollections;
        public Builder() {}
        public Builder(GetBdsInstanceSoftwareUpdatesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bdsInstanceId = defaults.bdsInstanceId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.softwareUpdateCollections = defaults.softwareUpdateCollections;
        }

        @CustomType.Setter
        public Builder bdsInstanceId(String bdsInstanceId) {
            if (bdsInstanceId == null) {
              throw new MissingRequiredPropertyException("GetBdsInstanceSoftwareUpdatesResult", "bdsInstanceId");
            }
            this.bdsInstanceId = bdsInstanceId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetBdsInstanceSoftwareUpdatesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetBdsInstanceSoftwareUpdatesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetBdsInstanceSoftwareUpdatesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder softwareUpdateCollections(List<GetBdsInstanceSoftwareUpdatesSoftwareUpdateCollection> softwareUpdateCollections) {
            if (softwareUpdateCollections == null) {
              throw new MissingRequiredPropertyException("GetBdsInstanceSoftwareUpdatesResult", "softwareUpdateCollections");
            }
            this.softwareUpdateCollections = softwareUpdateCollections;
            return this;
        }
        public Builder softwareUpdateCollections(GetBdsInstanceSoftwareUpdatesSoftwareUpdateCollection... softwareUpdateCollections) {
            return softwareUpdateCollections(List.of(softwareUpdateCollections));
        }
        public GetBdsInstanceSoftwareUpdatesResult build() {
            final var _resultValue = new GetBdsInstanceSoftwareUpdatesResult();
            _resultValue.bdsInstanceId = bdsInstanceId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.softwareUpdateCollections = softwareUpdateCollections;
            return _resultValue;
        }
    }
}
