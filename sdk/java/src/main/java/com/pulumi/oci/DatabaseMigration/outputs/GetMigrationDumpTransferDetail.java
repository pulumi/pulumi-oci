// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationDumpTransferDetailSource;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationDumpTransferDetailTarget;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMigrationDumpTransferDetail {
    /**
     * @return Optional additional properties for dump transfer in source or target host. Default kind is CURL
     * 
     */
    private List<GetMigrationDumpTransferDetailSource> sources;
    /**
     * @return Optional additional properties for dump transfer in source or target host. Default kind is CURL
     * 
     */
    private List<GetMigrationDumpTransferDetailTarget> targets;

    private GetMigrationDumpTransferDetail() {}
    /**
     * @return Optional additional properties for dump transfer in source or target host. Default kind is CURL
     * 
     */
    public List<GetMigrationDumpTransferDetailSource> sources() {
        return this.sources;
    }
    /**
     * @return Optional additional properties for dump transfer in source or target host. Default kind is CURL
     * 
     */
    public List<GetMigrationDumpTransferDetailTarget> targets() {
        return this.targets;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationDumpTransferDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetMigrationDumpTransferDetailSource> sources;
        private List<GetMigrationDumpTransferDetailTarget> targets;
        public Builder() {}
        public Builder(GetMigrationDumpTransferDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.sources = defaults.sources;
    	      this.targets = defaults.targets;
        }

        @CustomType.Setter
        public Builder sources(List<GetMigrationDumpTransferDetailSource> sources) {
            this.sources = Objects.requireNonNull(sources);
            return this;
        }
        public Builder sources(GetMigrationDumpTransferDetailSource... sources) {
            return sources(List.of(sources));
        }
        @CustomType.Setter
        public Builder targets(List<GetMigrationDumpTransferDetailTarget> targets) {
            this.targets = Objects.requireNonNull(targets);
            return this;
        }
        public Builder targets(GetMigrationDumpTransferDetailTarget... targets) {
            return targets(List.of(targets));
        }
        public GetMigrationDumpTransferDetail build() {
            final var o = new GetMigrationDumpTransferDetail();
            o.sources = sources;
            o.targets = targets;
            return o;
        }
    }
}