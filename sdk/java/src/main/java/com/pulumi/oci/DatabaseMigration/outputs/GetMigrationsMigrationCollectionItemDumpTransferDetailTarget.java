// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMigrationsMigrationCollectionItemDumpTransferDetailTarget {
    /**
     * @return Type of dump transfer to use during migration in source or target host. Default kind is CURL
     * 
     */
    private String kind;
    /**
     * @return Path to the Oracle Cloud Infrastructure CLI installation in the node.
     * 
     */
    private String ociHome;

    private GetMigrationsMigrationCollectionItemDumpTransferDetailTarget() {}
    /**
     * @return Type of dump transfer to use during migration in source or target host. Default kind is CURL
     * 
     */
    public String kind() {
        return this.kind;
    }
    /**
     * @return Path to the Oracle Cloud Infrastructure CLI installation in the node.
     * 
     */
    public String ociHome() {
        return this.ociHome;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationsMigrationCollectionItemDumpTransferDetailTarget defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String kind;
        private String ociHome;
        public Builder() {}
        public Builder(GetMigrationsMigrationCollectionItemDumpTransferDetailTarget defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.kind = defaults.kind;
    	      this.ociHome = defaults.ociHome;
        }

        @CustomType.Setter
        public Builder kind(String kind) {
            this.kind = Objects.requireNonNull(kind);
            return this;
        }
        @CustomType.Setter
        public Builder ociHome(String ociHome) {
            this.ociHome = Objects.requireNonNull(ociHome);
            return this;
        }
        public GetMigrationsMigrationCollectionItemDumpTransferDetailTarget build() {
            final var o = new GetMigrationsMigrationCollectionItemDumpTransferDetailTarget();
            o.kind = kind;
            o.ociHome = ociHome;
            return o;
        }
    }
}