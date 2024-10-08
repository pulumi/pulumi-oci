// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.outputs.GetInstallationSiteItemBlocklist;
import com.pulumi.oci.Jms.outputs.GetInstallationSiteItemJre;
import com.pulumi.oci.Jms.outputs.GetInstallationSiteItemOperatingSystem;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstallationSiteItem {
    /**
     * @return The approximate count of applications running on this installation
     * 
     */
    private Integer approximateApplicationCount;
    /**
     * @return The list of operations that are blocklisted.
     * 
     */
    private List<GetInstallationSiteItemBlocklist> blocklists;
    /**
     * @return The unique identifier for the installation of Java Runtime at a specific path on a specific operating system.
     * 
     */
    private String installationKey;
    /**
     * @return The essential properties to identify a Java Runtime.
     * 
     */
    private List<GetInstallationSiteItemJre> jres;
    /**
     * @return The Fleet-unique identifier of the related managed instance.
     * 
     */
    private String managedInstanceId;
    /**
     * @return Operating System of the platform on which the Java Runtime was reported.
     * 
     */
    private List<GetInstallationSiteItemOperatingSystem> operatingSystems;
    /**
     * @return The file system path of the installation.
     * 
     */
    private String path;
    /**
     * @return The security status of the Java Runtime.
     * 
     */
    private String securityStatus;
    /**
     * @return The lifecycle state of the installation site.
     * 
     */
    private String state;
    /**
     * @return The date and time the resource was _last_ reported to JMS. This is potentially _after_ the specified time period provided by the filters. For example, a resource can be last reported to JMS before the start of a specified time period, if it is also reported during the time period.
     * 
     */
    private String timeLastSeen;

    private GetInstallationSiteItem() {}
    /**
     * @return The approximate count of applications running on this installation
     * 
     */
    public Integer approximateApplicationCount() {
        return this.approximateApplicationCount;
    }
    /**
     * @return The list of operations that are blocklisted.
     * 
     */
    public List<GetInstallationSiteItemBlocklist> blocklists() {
        return this.blocklists;
    }
    /**
     * @return The unique identifier for the installation of Java Runtime at a specific path on a specific operating system.
     * 
     */
    public String installationKey() {
        return this.installationKey;
    }
    /**
     * @return The essential properties to identify a Java Runtime.
     * 
     */
    public List<GetInstallationSiteItemJre> jres() {
        return this.jres;
    }
    /**
     * @return The Fleet-unique identifier of the related managed instance.
     * 
     */
    public String managedInstanceId() {
        return this.managedInstanceId;
    }
    /**
     * @return Operating System of the platform on which the Java Runtime was reported.
     * 
     */
    public List<GetInstallationSiteItemOperatingSystem> operatingSystems() {
        return this.operatingSystems;
    }
    /**
     * @return The file system path of the installation.
     * 
     */
    public String path() {
        return this.path;
    }
    /**
     * @return The security status of the Java Runtime.
     * 
     */
    public String securityStatus() {
        return this.securityStatus;
    }
    /**
     * @return The lifecycle state of the installation site.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the resource was _last_ reported to JMS. This is potentially _after_ the specified time period provided by the filters. For example, a resource can be last reported to JMS before the start of a specified time period, if it is also reported during the time period.
     * 
     */
    public String timeLastSeen() {
        return this.timeLastSeen;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstallationSiteItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer approximateApplicationCount;
        private List<GetInstallationSiteItemBlocklist> blocklists;
        private String installationKey;
        private List<GetInstallationSiteItemJre> jres;
        private String managedInstanceId;
        private List<GetInstallationSiteItemOperatingSystem> operatingSystems;
        private String path;
        private String securityStatus;
        private String state;
        private String timeLastSeen;
        public Builder() {}
        public Builder(GetInstallationSiteItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.approximateApplicationCount = defaults.approximateApplicationCount;
    	      this.blocklists = defaults.blocklists;
    	      this.installationKey = defaults.installationKey;
    	      this.jres = defaults.jres;
    	      this.managedInstanceId = defaults.managedInstanceId;
    	      this.operatingSystems = defaults.operatingSystems;
    	      this.path = defaults.path;
    	      this.securityStatus = defaults.securityStatus;
    	      this.state = defaults.state;
    	      this.timeLastSeen = defaults.timeLastSeen;
        }

        @CustomType.Setter
        public Builder approximateApplicationCount(Integer approximateApplicationCount) {
            if (approximateApplicationCount == null) {
              throw new MissingRequiredPropertyException("GetInstallationSiteItem", "approximateApplicationCount");
            }
            this.approximateApplicationCount = approximateApplicationCount;
            return this;
        }
        @CustomType.Setter
        public Builder blocklists(List<GetInstallationSiteItemBlocklist> blocklists) {
            if (blocklists == null) {
              throw new MissingRequiredPropertyException("GetInstallationSiteItem", "blocklists");
            }
            this.blocklists = blocklists;
            return this;
        }
        public Builder blocklists(GetInstallationSiteItemBlocklist... blocklists) {
            return blocklists(List.of(blocklists));
        }
        @CustomType.Setter
        public Builder installationKey(String installationKey) {
            if (installationKey == null) {
              throw new MissingRequiredPropertyException("GetInstallationSiteItem", "installationKey");
            }
            this.installationKey = installationKey;
            return this;
        }
        @CustomType.Setter
        public Builder jres(List<GetInstallationSiteItemJre> jres) {
            if (jres == null) {
              throw new MissingRequiredPropertyException("GetInstallationSiteItem", "jres");
            }
            this.jres = jres;
            return this;
        }
        public Builder jres(GetInstallationSiteItemJre... jres) {
            return jres(List.of(jres));
        }
        @CustomType.Setter
        public Builder managedInstanceId(String managedInstanceId) {
            if (managedInstanceId == null) {
              throw new MissingRequiredPropertyException("GetInstallationSiteItem", "managedInstanceId");
            }
            this.managedInstanceId = managedInstanceId;
            return this;
        }
        @CustomType.Setter
        public Builder operatingSystems(List<GetInstallationSiteItemOperatingSystem> operatingSystems) {
            if (operatingSystems == null) {
              throw new MissingRequiredPropertyException("GetInstallationSiteItem", "operatingSystems");
            }
            this.operatingSystems = operatingSystems;
            return this;
        }
        public Builder operatingSystems(GetInstallationSiteItemOperatingSystem... operatingSystems) {
            return operatingSystems(List.of(operatingSystems));
        }
        @CustomType.Setter
        public Builder path(String path) {
            if (path == null) {
              throw new MissingRequiredPropertyException("GetInstallationSiteItem", "path");
            }
            this.path = path;
            return this;
        }
        @CustomType.Setter
        public Builder securityStatus(String securityStatus) {
            if (securityStatus == null) {
              throw new MissingRequiredPropertyException("GetInstallationSiteItem", "securityStatus");
            }
            this.securityStatus = securityStatus;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetInstallationSiteItem", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastSeen(String timeLastSeen) {
            if (timeLastSeen == null) {
              throw new MissingRequiredPropertyException("GetInstallationSiteItem", "timeLastSeen");
            }
            this.timeLastSeen = timeLastSeen;
            return this;
        }
        public GetInstallationSiteItem build() {
            final var _resultValue = new GetInstallationSiteItem();
            _resultValue.approximateApplicationCount = approximateApplicationCount;
            _resultValue.blocklists = blocklists;
            _resultValue.installationKey = installationKey;
            _resultValue.jres = jres;
            _resultValue.managedInstanceId = managedInstanceId;
            _resultValue.operatingSystems = operatingSystems;
            _resultValue.path = path;
            _resultValue.securityStatus = securityStatus;
            _resultValue.state = state;
            _resultValue.timeLastSeen = timeLastSeen;
            return _resultValue;
        }
    }
}
