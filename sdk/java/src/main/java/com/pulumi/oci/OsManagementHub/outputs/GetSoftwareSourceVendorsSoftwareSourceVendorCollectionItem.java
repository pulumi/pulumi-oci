// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSoftwareSourceVendorsSoftwareSourceVendorCollectionItem {
    /**
     * @return List of corresponding archTypes.
     * 
     */
    private List<String> archTypes;
    /**
     * @return The name of the entity to be queried.
     * 
     */
    private String name;
    /**
     * @return List of corresponding osFamilies.
     * 
     */
    private List<String> osFamilies;

    private GetSoftwareSourceVendorsSoftwareSourceVendorCollectionItem() {}
    /**
     * @return List of corresponding archTypes.
     * 
     */
    public List<String> archTypes() {
        return this.archTypes;
    }
    /**
     * @return The name of the entity to be queried.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return List of corresponding osFamilies.
     * 
     */
    public List<String> osFamilies() {
        return this.osFamilies;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSoftwareSourceVendorsSoftwareSourceVendorCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> archTypes;
        private String name;
        private List<String> osFamilies;
        public Builder() {}
        public Builder(GetSoftwareSourceVendorsSoftwareSourceVendorCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.archTypes = defaults.archTypes;
    	      this.name = defaults.name;
    	      this.osFamilies = defaults.osFamilies;
        }

        @CustomType.Setter
        public Builder archTypes(List<String> archTypes) {
            this.archTypes = Objects.requireNonNull(archTypes);
            return this;
        }
        public Builder archTypes(String... archTypes) {
            return archTypes(List.of(archTypes));
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder osFamilies(List<String> osFamilies) {
            this.osFamilies = Objects.requireNonNull(osFamilies);
            return this;
        }
        public Builder osFamilies(String... osFamilies) {
            return osFamilies(List.of(osFamilies));
        }
        public GetSoftwareSourceVendorsSoftwareSourceVendorCollectionItem build() {
            final var o = new GetSoftwareSourceVendorsSoftwareSourceVendorCollectionItem();
            o.archTypes = archTypes;
            o.name = name;
            o.osFamilies = osFamilies;
            return o;
        }
    }
}