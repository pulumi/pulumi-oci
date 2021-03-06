// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailSettingExtract;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailSettingReplicat;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMigrationsMigrationCollectionItemGoldenGateDetailSetting {
    /**
     * @return ODMS will monitor GoldenGate end-to-end latency until the lag time is lower than the specified value in seconds.
     * 
     */
    private final Integer acceptableLag;
    /**
     * @return Parameters for Extract processes.
     * 
     */
    private final List<GetMigrationsMigrationCollectionItemGoldenGateDetailSettingExtract> extracts;
    /**
     * @return Parameters for Replicat processes.
     * 
     */
    private final List<GetMigrationsMigrationCollectionItemGoldenGateDetailSettingReplicat> replicats;

    @CustomType.Constructor
    private GetMigrationsMigrationCollectionItemGoldenGateDetailSetting(
        @CustomType.Parameter("acceptableLag") Integer acceptableLag,
        @CustomType.Parameter("extracts") List<GetMigrationsMigrationCollectionItemGoldenGateDetailSettingExtract> extracts,
        @CustomType.Parameter("replicats") List<GetMigrationsMigrationCollectionItemGoldenGateDetailSettingReplicat> replicats) {
        this.acceptableLag = acceptableLag;
        this.extracts = extracts;
        this.replicats = replicats;
    }

    /**
     * @return ODMS will monitor GoldenGate end-to-end latency until the lag time is lower than the specified value in seconds.
     * 
     */
    public Integer acceptableLag() {
        return this.acceptableLag;
    }
    /**
     * @return Parameters for Extract processes.
     * 
     */
    public List<GetMigrationsMigrationCollectionItemGoldenGateDetailSettingExtract> extracts() {
        return this.extracts;
    }
    /**
     * @return Parameters for Replicat processes.
     * 
     */
    public List<GetMigrationsMigrationCollectionItemGoldenGateDetailSettingReplicat> replicats() {
        return this.replicats;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationsMigrationCollectionItemGoldenGateDetailSetting defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer acceptableLag;
        private List<GetMigrationsMigrationCollectionItemGoldenGateDetailSettingExtract> extracts;
        private List<GetMigrationsMigrationCollectionItemGoldenGateDetailSettingReplicat> replicats;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMigrationsMigrationCollectionItemGoldenGateDetailSetting defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.acceptableLag = defaults.acceptableLag;
    	      this.extracts = defaults.extracts;
    	      this.replicats = defaults.replicats;
        }

        public Builder acceptableLag(Integer acceptableLag) {
            this.acceptableLag = Objects.requireNonNull(acceptableLag);
            return this;
        }
        public Builder extracts(List<GetMigrationsMigrationCollectionItemGoldenGateDetailSettingExtract> extracts) {
            this.extracts = Objects.requireNonNull(extracts);
            return this;
        }
        public Builder extracts(GetMigrationsMigrationCollectionItemGoldenGateDetailSettingExtract... extracts) {
            return extracts(List.of(extracts));
        }
        public Builder replicats(List<GetMigrationsMigrationCollectionItemGoldenGateDetailSettingReplicat> replicats) {
            this.replicats = Objects.requireNonNull(replicats);
            return this;
        }
        public Builder replicats(GetMigrationsMigrationCollectionItemGoldenGateDetailSettingReplicat... replicats) {
            return replicats(List.of(replicats));
        }        public GetMigrationsMigrationCollectionItemGoldenGateDetailSetting build() {
            return new GetMigrationsMigrationCollectionItemGoldenGateDetailSetting(acceptableLag, extracts, replicats);
        }
    }
}
