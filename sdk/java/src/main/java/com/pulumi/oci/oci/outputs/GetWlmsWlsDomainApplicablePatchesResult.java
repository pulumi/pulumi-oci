// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.oci.outputs.GetWlmsWlsDomainApplicablePatchesApplicablePatchCollection;
import com.pulumi.oci.oci.outputs.GetWlmsWlsDomainApplicablePatchesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetWlmsWlsDomainApplicablePatchesResult {
    /**
     * @return The list of applicable_patch_collection.
     * 
     */
    private List<GetWlmsWlsDomainApplicablePatchesApplicablePatchCollection> applicablePatchCollections;
    private @Nullable List<GetWlmsWlsDomainApplicablePatchesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String wlsDomainId;

    private GetWlmsWlsDomainApplicablePatchesResult() {}
    /**
     * @return The list of applicable_patch_collection.
     * 
     */
    public List<GetWlmsWlsDomainApplicablePatchesApplicablePatchCollection> applicablePatchCollections() {
        return this.applicablePatchCollections;
    }
    public List<GetWlmsWlsDomainApplicablePatchesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String wlsDomainId() {
        return this.wlsDomainId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWlmsWlsDomainApplicablePatchesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWlmsWlsDomainApplicablePatchesApplicablePatchCollection> applicablePatchCollections;
        private @Nullable List<GetWlmsWlsDomainApplicablePatchesFilter> filters;
        private String id;
        private String wlsDomainId;
        public Builder() {}
        public Builder(GetWlmsWlsDomainApplicablePatchesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicablePatchCollections = defaults.applicablePatchCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.wlsDomainId = defaults.wlsDomainId;
        }

        @CustomType.Setter
        public Builder applicablePatchCollections(List<GetWlmsWlsDomainApplicablePatchesApplicablePatchCollection> applicablePatchCollections) {
            if (applicablePatchCollections == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainApplicablePatchesResult", "applicablePatchCollections");
            }
            this.applicablePatchCollections = applicablePatchCollections;
            return this;
        }
        public Builder applicablePatchCollections(GetWlmsWlsDomainApplicablePatchesApplicablePatchCollection... applicablePatchCollections) {
            return applicablePatchCollections(List.of(applicablePatchCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetWlmsWlsDomainApplicablePatchesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetWlmsWlsDomainApplicablePatchesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainApplicablePatchesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder wlsDomainId(String wlsDomainId) {
            if (wlsDomainId == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainApplicablePatchesResult", "wlsDomainId");
            }
            this.wlsDomainId = wlsDomainId;
            return this;
        }
        public GetWlmsWlsDomainApplicablePatchesResult build() {
            final var _resultValue = new GetWlmsWlsDomainApplicablePatchesResult();
            _resultValue.applicablePatchCollections = applicablePatchCollections;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.wlsDomainId = wlsDomainId;
            return _resultValue;
        }
    }
}
