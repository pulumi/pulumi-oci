// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.DbSystemsUpgradeIormConfigCachDbPlan;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DbSystemsUpgradeIormConfigCach {
    /**
     * @return An array of IORM settings for all the database in the Exadata DB system.
     * 
     */
    private @Nullable List<DbSystemsUpgradeIormConfigCachDbPlan> dbPlans;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private @Nullable String lifecycleDetails;
    /**
     * @return The current value for the IORM objective. The default is `AUTO`.
     * 
     */
    private @Nullable String objective;
    /**
     * @return The current state of the DB system.
     * 
     */
    private @Nullable String state;

    private DbSystemsUpgradeIormConfigCach() {}
    /**
     * @return An array of IORM settings for all the database in the Exadata DB system.
     * 
     */
    public List<DbSystemsUpgradeIormConfigCachDbPlan> dbPlans() {
        return this.dbPlans == null ? List.of() : this.dbPlans;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Optional<String> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }
    /**
     * @return The current value for the IORM objective. The default is `AUTO`.
     * 
     */
    public Optional<String> objective() {
        return Optional.ofNullable(this.objective);
    }
    /**
     * @return The current state of the DB system.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DbSystemsUpgradeIormConfigCach defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<DbSystemsUpgradeIormConfigCachDbPlan> dbPlans;
        private @Nullable String lifecycleDetails;
        private @Nullable String objective;
        private @Nullable String state;
        public Builder() {}
        public Builder(DbSystemsUpgradeIormConfigCach defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dbPlans = defaults.dbPlans;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.objective = defaults.objective;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder dbPlans(@Nullable List<DbSystemsUpgradeIormConfigCachDbPlan> dbPlans) {

            this.dbPlans = dbPlans;
            return this;
        }
        public Builder dbPlans(DbSystemsUpgradeIormConfigCachDbPlan... dbPlans) {
            return dbPlans(List.of(dbPlans));
        }
        @CustomType.Setter
        public Builder lifecycleDetails(@Nullable String lifecycleDetails) {

            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder objective(@Nullable String objective) {

            this.objective = objective;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public DbSystemsUpgradeIormConfigCach build() {
            final var _resultValue = new DbSystemsUpgradeIormConfigCach();
            _resultValue.dbPlans = dbPlans;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.objective = objective;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
