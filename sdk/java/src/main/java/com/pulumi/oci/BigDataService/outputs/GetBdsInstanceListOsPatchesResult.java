// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstanceListOsPatchesFilter;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstanceListOsPatchesOsPatch;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetBdsInstanceListOsPatchesResult {
    private String bdsInstanceId;
    private @Nullable List<GetBdsInstanceListOsPatchesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of os_patches.
     * 
     */
    private List<GetBdsInstanceListOsPatchesOsPatch> osPatches;

    private GetBdsInstanceListOsPatchesResult() {}
    public String bdsInstanceId() {
        return this.bdsInstanceId;
    }
    public List<GetBdsInstanceListOsPatchesFilter> filters() {
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
     * @return The list of os_patches.
     * 
     */
    public List<GetBdsInstanceListOsPatchesOsPatch> osPatches() {
        return this.osPatches;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBdsInstanceListOsPatchesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String bdsInstanceId;
        private @Nullable List<GetBdsInstanceListOsPatchesFilter> filters;
        private String id;
        private List<GetBdsInstanceListOsPatchesOsPatch> osPatches;
        public Builder() {}
        public Builder(GetBdsInstanceListOsPatchesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bdsInstanceId = defaults.bdsInstanceId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.osPatches = defaults.osPatches;
        }

        @CustomType.Setter
        public Builder bdsInstanceId(String bdsInstanceId) {
            if (bdsInstanceId == null) {
              throw new MissingRequiredPropertyException("GetBdsInstanceListOsPatchesResult", "bdsInstanceId");
            }
            this.bdsInstanceId = bdsInstanceId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetBdsInstanceListOsPatchesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetBdsInstanceListOsPatchesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetBdsInstanceListOsPatchesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder osPatches(List<GetBdsInstanceListOsPatchesOsPatch> osPatches) {
            if (osPatches == null) {
              throw new MissingRequiredPropertyException("GetBdsInstanceListOsPatchesResult", "osPatches");
            }
            this.osPatches = osPatches;
            return this;
        }
        public Builder osPatches(GetBdsInstanceListOsPatchesOsPatch... osPatches) {
            return osPatches(List.of(osPatches));
        }
        public GetBdsInstanceListOsPatchesResult build() {
            final var _resultValue = new GetBdsInstanceListOsPatchesResult();
            _resultValue.bdsInstanceId = bdsInstanceId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.osPatches = osPatches;
            return _resultValue;
        }
    }
}
