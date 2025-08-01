// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.oci.outputs.GetWlmsWlsDomainServerInstalledPatchesFilter;
import com.pulumi.oci.oci.outputs.GetWlmsWlsDomainServerInstalledPatchesInstalledPatchCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetWlmsWlsDomainServerInstalledPatchesResult {
    private @Nullable List<GetWlmsWlsDomainServerInstalledPatchesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of installed_patch_collection.
     * 
     */
    private List<GetWlmsWlsDomainServerInstalledPatchesInstalledPatchCollection> installedPatchCollections;
    private String serverId;
    private String wlsDomainId;

    private GetWlmsWlsDomainServerInstalledPatchesResult() {}
    public List<GetWlmsWlsDomainServerInstalledPatchesFilter> filters() {
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
     * @return The list of installed_patch_collection.
     * 
     */
    public List<GetWlmsWlsDomainServerInstalledPatchesInstalledPatchCollection> installedPatchCollections() {
        return this.installedPatchCollections;
    }
    public String serverId() {
        return this.serverId;
    }
    public String wlsDomainId() {
        return this.wlsDomainId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWlmsWlsDomainServerInstalledPatchesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetWlmsWlsDomainServerInstalledPatchesFilter> filters;
        private String id;
        private List<GetWlmsWlsDomainServerInstalledPatchesInstalledPatchCollection> installedPatchCollections;
        private String serverId;
        private String wlsDomainId;
        public Builder() {}
        public Builder(GetWlmsWlsDomainServerInstalledPatchesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.installedPatchCollections = defaults.installedPatchCollections;
    	      this.serverId = defaults.serverId;
    	      this.wlsDomainId = defaults.wlsDomainId;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetWlmsWlsDomainServerInstalledPatchesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetWlmsWlsDomainServerInstalledPatchesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainServerInstalledPatchesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder installedPatchCollections(List<GetWlmsWlsDomainServerInstalledPatchesInstalledPatchCollection> installedPatchCollections) {
            if (installedPatchCollections == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainServerInstalledPatchesResult", "installedPatchCollections");
            }
            this.installedPatchCollections = installedPatchCollections;
            return this;
        }
        public Builder installedPatchCollections(GetWlmsWlsDomainServerInstalledPatchesInstalledPatchCollection... installedPatchCollections) {
            return installedPatchCollections(List.of(installedPatchCollections));
        }
        @CustomType.Setter
        public Builder serverId(String serverId) {
            if (serverId == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainServerInstalledPatchesResult", "serverId");
            }
            this.serverId = serverId;
            return this;
        }
        @CustomType.Setter
        public Builder wlsDomainId(String wlsDomainId) {
            if (wlsDomainId == null) {
              throw new MissingRequiredPropertyException("GetWlmsWlsDomainServerInstalledPatchesResult", "wlsDomainId");
            }
            this.wlsDomainId = wlsDomainId;
            return this;
        }
        public GetWlmsWlsDomainServerInstalledPatchesResult build() {
            final var _resultValue = new GetWlmsWlsDomainServerInstalledPatchesResult();
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.installedPatchCollections = installedPatchCollections;
            _resultValue.serverId = serverId;
            _resultValue.wlsDomainId = wlsDomainId;
            return _resultValue;
        }
    }
}
