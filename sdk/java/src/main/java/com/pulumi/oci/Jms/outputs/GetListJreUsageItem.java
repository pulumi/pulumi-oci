// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Jms.outputs.GetListJreUsageItemOperatingSystem;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetListJreUsageItem {
    /**
     * @return The approximate count of the applications running on this Java Runtime.
     * 
     */
    private final Integer approximateApplicationCount;
    /**
     * @return The approximate count of installations that are installations of this Java Runtime.
     * 
     */
    private final Integer approximateInstallationCount;
    /**
     * @return The approximate count of the managed instances that report this Java Runtime.
     * 
     */
    private final Integer approximateManagedInstanceCount;
    /**
     * @return The approximate count of work requests working on this Java Runtime.
     * 
     */
    private final Integer approximatePendingWorkRequestCount;
    /**
     * @return The distribution of a Java Runtime is the name of the lineage of product to which it belongs, for example _Java(TM) SE Runtime Environment_.
     * 
     */
    private final String distribution;
    /**
     * @return The End of Support Life (EOSL) date of the Java Runtime (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    private final String endOfSupportLifeDate;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related fleet.  This property value is present only for /actions/listJreUsage.
     * 
     */
    private final String fleetId;
    /**
     * @return The internal identifier of the Java Runtime.
     * 
     */
    private final String id;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related managed instance. This property value is present only for /actions/listJreUsage.
     * 
     */
    private final String managedInstanceId;
    /**
     * @return The operating systems that have this Java Runtime installed.
     * 
     */
    private final List<GetListJreUsageItemOperatingSystem> operatingSystems;
    /**
     * @return The release date of the Java Runtime (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    private final String releaseDate;
    /**
     * @return The security status of the Java Runtime.
     * 
     */
    private final String securityStatus;
    /**
     * @return The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    private final String timeEnd;
    /**
     * @return The date and time the resource was _first_ reported to JMS. This is potentially _before_ the specified time period provided by the filters. For example, a resource can be first reported to JMS before the start of a specified time period, if it is also reported during the time period.
     * 
     */
    private final String timeFirstSeen;
    /**
     * @return The date and time the resource was _last_ reported to JMS. This is potentially _after_ the specified time period provided by the filters. For example, a resource can be last reported to JMS before the start of a specified time period, if it is also reported during the time period.
     * 
     */
    private final String timeLastSeen;
    /**
     * @return The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    private final String timeStart;
    /**
     * @return The vendor of the Java Runtime.
     * 
     */
    private final String vendor;
    /**
     * @return The version of the Java Runtime.
     * 
     */
    private final String version;

    @CustomType.Constructor
    private GetListJreUsageItem(
        @CustomType.Parameter("approximateApplicationCount") Integer approximateApplicationCount,
        @CustomType.Parameter("approximateInstallationCount") Integer approximateInstallationCount,
        @CustomType.Parameter("approximateManagedInstanceCount") Integer approximateManagedInstanceCount,
        @CustomType.Parameter("approximatePendingWorkRequestCount") Integer approximatePendingWorkRequestCount,
        @CustomType.Parameter("distribution") String distribution,
        @CustomType.Parameter("endOfSupportLifeDate") String endOfSupportLifeDate,
        @CustomType.Parameter("fleetId") String fleetId,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("managedInstanceId") String managedInstanceId,
        @CustomType.Parameter("operatingSystems") List<GetListJreUsageItemOperatingSystem> operatingSystems,
        @CustomType.Parameter("releaseDate") String releaseDate,
        @CustomType.Parameter("securityStatus") String securityStatus,
        @CustomType.Parameter("timeEnd") String timeEnd,
        @CustomType.Parameter("timeFirstSeen") String timeFirstSeen,
        @CustomType.Parameter("timeLastSeen") String timeLastSeen,
        @CustomType.Parameter("timeStart") String timeStart,
        @CustomType.Parameter("vendor") String vendor,
        @CustomType.Parameter("version") String version) {
        this.approximateApplicationCount = approximateApplicationCount;
        this.approximateInstallationCount = approximateInstallationCount;
        this.approximateManagedInstanceCount = approximateManagedInstanceCount;
        this.approximatePendingWorkRequestCount = approximatePendingWorkRequestCount;
        this.distribution = distribution;
        this.endOfSupportLifeDate = endOfSupportLifeDate;
        this.fleetId = fleetId;
        this.id = id;
        this.managedInstanceId = managedInstanceId;
        this.operatingSystems = operatingSystems;
        this.releaseDate = releaseDate;
        this.securityStatus = securityStatus;
        this.timeEnd = timeEnd;
        this.timeFirstSeen = timeFirstSeen;
        this.timeLastSeen = timeLastSeen;
        this.timeStart = timeStart;
        this.vendor = vendor;
        this.version = version;
    }

    /**
     * @return The approximate count of the applications running on this Java Runtime.
     * 
     */
    public Integer approximateApplicationCount() {
        return this.approximateApplicationCount;
    }
    /**
     * @return The approximate count of installations that are installations of this Java Runtime.
     * 
     */
    public Integer approximateInstallationCount() {
        return this.approximateInstallationCount;
    }
    /**
     * @return The approximate count of the managed instances that report this Java Runtime.
     * 
     */
    public Integer approximateManagedInstanceCount() {
        return this.approximateManagedInstanceCount;
    }
    /**
     * @return The approximate count of work requests working on this Java Runtime.
     * 
     */
    public Integer approximatePendingWorkRequestCount() {
        return this.approximatePendingWorkRequestCount;
    }
    /**
     * @return The distribution of a Java Runtime is the name of the lineage of product to which it belongs, for example _Java(TM) SE Runtime Environment_.
     * 
     */
    public String distribution() {
        return this.distribution;
    }
    /**
     * @return The End of Support Life (EOSL) date of the Java Runtime (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public String endOfSupportLifeDate() {
        return this.endOfSupportLifeDate;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related fleet.  This property value is present only for /actions/listJreUsage.
     * 
     */
    public String fleetId() {
        return this.fleetId;
    }
    /**
     * @return The internal identifier of the Java Runtime.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related managed instance. This property value is present only for /actions/listJreUsage.
     * 
     */
    public String managedInstanceId() {
        return this.managedInstanceId;
    }
    /**
     * @return The operating systems that have this Java Runtime installed.
     * 
     */
    public List<GetListJreUsageItemOperatingSystem> operatingSystems() {
        return this.operatingSystems;
    }
    /**
     * @return The release date of the Java Runtime (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public String releaseDate() {
        return this.releaseDate;
    }
    /**
     * @return The security status of the Java Runtime.
     * 
     */
    public String securityStatus() {
        return this.securityStatus;
    }
    /**
     * @return The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public String timeEnd() {
        return this.timeEnd;
    }
    /**
     * @return The date and time the resource was _first_ reported to JMS. This is potentially _before_ the specified time period provided by the filters. For example, a resource can be first reported to JMS before the start of a specified time period, if it is also reported during the time period.
     * 
     */
    public String timeFirstSeen() {
        return this.timeFirstSeen;
    }
    /**
     * @return The date and time the resource was _last_ reported to JMS. This is potentially _after_ the specified time period provided by the filters. For example, a resource can be last reported to JMS before the start of a specified time period, if it is also reported during the time period.
     * 
     */
    public String timeLastSeen() {
        return this.timeLastSeen;
    }
    /**
     * @return The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public String timeStart() {
        return this.timeStart;
    }
    /**
     * @return The vendor of the Java Runtime.
     * 
     */
    public String vendor() {
        return this.vendor;
    }
    /**
     * @return The version of the Java Runtime.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetListJreUsageItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer approximateApplicationCount;
        private Integer approximateInstallationCount;
        private Integer approximateManagedInstanceCount;
        private Integer approximatePendingWorkRequestCount;
        private String distribution;
        private String endOfSupportLifeDate;
        private String fleetId;
        private String id;
        private String managedInstanceId;
        private List<GetListJreUsageItemOperatingSystem> operatingSystems;
        private String releaseDate;
        private String securityStatus;
        private String timeEnd;
        private String timeFirstSeen;
        private String timeLastSeen;
        private String timeStart;
        private String vendor;
        private String version;

        public Builder() {
    	      // Empty
        }

        public Builder(GetListJreUsageItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.approximateApplicationCount = defaults.approximateApplicationCount;
    	      this.approximateInstallationCount = defaults.approximateInstallationCount;
    	      this.approximateManagedInstanceCount = defaults.approximateManagedInstanceCount;
    	      this.approximatePendingWorkRequestCount = defaults.approximatePendingWorkRequestCount;
    	      this.distribution = defaults.distribution;
    	      this.endOfSupportLifeDate = defaults.endOfSupportLifeDate;
    	      this.fleetId = defaults.fleetId;
    	      this.id = defaults.id;
    	      this.managedInstanceId = defaults.managedInstanceId;
    	      this.operatingSystems = defaults.operatingSystems;
    	      this.releaseDate = defaults.releaseDate;
    	      this.securityStatus = defaults.securityStatus;
    	      this.timeEnd = defaults.timeEnd;
    	      this.timeFirstSeen = defaults.timeFirstSeen;
    	      this.timeLastSeen = defaults.timeLastSeen;
    	      this.timeStart = defaults.timeStart;
    	      this.vendor = defaults.vendor;
    	      this.version = defaults.version;
        }

        public Builder approximateApplicationCount(Integer approximateApplicationCount) {
            this.approximateApplicationCount = Objects.requireNonNull(approximateApplicationCount);
            return this;
        }
        public Builder approximateInstallationCount(Integer approximateInstallationCount) {
            this.approximateInstallationCount = Objects.requireNonNull(approximateInstallationCount);
            return this;
        }
        public Builder approximateManagedInstanceCount(Integer approximateManagedInstanceCount) {
            this.approximateManagedInstanceCount = Objects.requireNonNull(approximateManagedInstanceCount);
            return this;
        }
        public Builder approximatePendingWorkRequestCount(Integer approximatePendingWorkRequestCount) {
            this.approximatePendingWorkRequestCount = Objects.requireNonNull(approximatePendingWorkRequestCount);
            return this;
        }
        public Builder distribution(String distribution) {
            this.distribution = Objects.requireNonNull(distribution);
            return this;
        }
        public Builder endOfSupportLifeDate(String endOfSupportLifeDate) {
            this.endOfSupportLifeDate = Objects.requireNonNull(endOfSupportLifeDate);
            return this;
        }
        public Builder fleetId(String fleetId) {
            this.fleetId = Objects.requireNonNull(fleetId);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder managedInstanceId(String managedInstanceId) {
            this.managedInstanceId = Objects.requireNonNull(managedInstanceId);
            return this;
        }
        public Builder operatingSystems(List<GetListJreUsageItemOperatingSystem> operatingSystems) {
            this.operatingSystems = Objects.requireNonNull(operatingSystems);
            return this;
        }
        public Builder operatingSystems(GetListJreUsageItemOperatingSystem... operatingSystems) {
            return operatingSystems(List.of(operatingSystems));
        }
        public Builder releaseDate(String releaseDate) {
            this.releaseDate = Objects.requireNonNull(releaseDate);
            return this;
        }
        public Builder securityStatus(String securityStatus) {
            this.securityStatus = Objects.requireNonNull(securityStatus);
            return this;
        }
        public Builder timeEnd(String timeEnd) {
            this.timeEnd = Objects.requireNonNull(timeEnd);
            return this;
        }
        public Builder timeFirstSeen(String timeFirstSeen) {
            this.timeFirstSeen = Objects.requireNonNull(timeFirstSeen);
            return this;
        }
        public Builder timeLastSeen(String timeLastSeen) {
            this.timeLastSeen = Objects.requireNonNull(timeLastSeen);
            return this;
        }
        public Builder timeStart(String timeStart) {
            this.timeStart = Objects.requireNonNull(timeStart);
            return this;
        }
        public Builder vendor(String vendor) {
            this.vendor = Objects.requireNonNull(vendor);
            return this;
        }
        public Builder version(String version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }        public GetListJreUsageItem build() {
            return new GetListJreUsageItem(approximateApplicationCount, approximateInstallationCount, approximateManagedInstanceCount, approximatePendingWorkRequestCount, distribution, endOfSupportLifeDate, fleetId, id, managedInstanceId, operatingSystems, releaseDate, securityStatus, timeEnd, timeFirstSeen, timeLastSeen, timeStart, vendor, version);
        }
    }
}
