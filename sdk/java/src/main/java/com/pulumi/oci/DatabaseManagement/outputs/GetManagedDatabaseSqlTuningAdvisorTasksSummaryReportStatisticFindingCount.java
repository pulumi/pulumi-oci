// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticFindingCount {
    /**
     * @return The number of distinct SQL statements with alternative plan recommendations.
     * 
     */
    private final Integer alternatePlan;
    /**
     * @return The number of distinct SQL statements with implemented SQL profiles.
     * 
     */
    private final Integer implementedSqlProfile;
    /**
     * @return The number of distinct SQL statements with index recommendations.
     * 
     */
    private final Integer index;
    /**
     * @return The number of distinct SQL statements with recommended SQL profiles.
     * 
     */
    private final Integer recommendedSqlProfile;
    /**
     * @return The number of distinct SQL statements with restructured SQL recommendations.
     * 
     */
    private final Integer restructure;
    /**
     * @return The number of distinct SQL statements with stale or missing optimizer statistics recommendations.
     * 
     */
    private final Integer statistics;

    @CustomType.Constructor
    private GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticFindingCount(
        @CustomType.Parameter("alternatePlan") Integer alternatePlan,
        @CustomType.Parameter("implementedSqlProfile") Integer implementedSqlProfile,
        @CustomType.Parameter("index") Integer index,
        @CustomType.Parameter("recommendedSqlProfile") Integer recommendedSqlProfile,
        @CustomType.Parameter("restructure") Integer restructure,
        @CustomType.Parameter("statistics") Integer statistics) {
        this.alternatePlan = alternatePlan;
        this.implementedSqlProfile = implementedSqlProfile;
        this.index = index;
        this.recommendedSqlProfile = recommendedSqlProfile;
        this.restructure = restructure;
        this.statistics = statistics;
    }

    /**
     * @return The number of distinct SQL statements with alternative plan recommendations.
     * 
     */
    public Integer alternatePlan() {
        return this.alternatePlan;
    }
    /**
     * @return The number of distinct SQL statements with implemented SQL profiles.
     * 
     */
    public Integer implementedSqlProfile() {
        return this.implementedSqlProfile;
    }
    /**
     * @return The number of distinct SQL statements with index recommendations.
     * 
     */
    public Integer index() {
        return this.index;
    }
    /**
     * @return The number of distinct SQL statements with recommended SQL profiles.
     * 
     */
    public Integer recommendedSqlProfile() {
        return this.recommendedSqlProfile;
    }
    /**
     * @return The number of distinct SQL statements with restructured SQL recommendations.
     * 
     */
    public Integer restructure() {
        return this.restructure;
    }
    /**
     * @return The number of distinct SQL statements with stale or missing optimizer statistics recommendations.
     * 
     */
    public Integer statistics() {
        return this.statistics;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticFindingCount defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer alternatePlan;
        private Integer implementedSqlProfile;
        private Integer index;
        private Integer recommendedSqlProfile;
        private Integer restructure;
        private Integer statistics;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticFindingCount defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.alternatePlan = defaults.alternatePlan;
    	      this.implementedSqlProfile = defaults.implementedSqlProfile;
    	      this.index = defaults.index;
    	      this.recommendedSqlProfile = defaults.recommendedSqlProfile;
    	      this.restructure = defaults.restructure;
    	      this.statistics = defaults.statistics;
        }

        public Builder alternatePlan(Integer alternatePlan) {
            this.alternatePlan = Objects.requireNonNull(alternatePlan);
            return this;
        }
        public Builder implementedSqlProfile(Integer implementedSqlProfile) {
            this.implementedSqlProfile = Objects.requireNonNull(implementedSqlProfile);
            return this;
        }
        public Builder index(Integer index) {
            this.index = Objects.requireNonNull(index);
            return this;
        }
        public Builder recommendedSqlProfile(Integer recommendedSqlProfile) {
            this.recommendedSqlProfile = Objects.requireNonNull(recommendedSqlProfile);
            return this;
        }
        public Builder restructure(Integer restructure) {
            this.restructure = Objects.requireNonNull(restructure);
            return this;
        }
        public Builder statistics(Integer statistics) {
            this.statistics = Objects.requireNonNull(statistics);
            return this;
        }        public GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticFindingCount build() {
            return new GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticFindingCount(alternatePlan, implementedSqlProfile, index, recommendedSqlProfile, restructure, statistics);
        }
    }
}
