// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetInstallationSiteArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetInstallationSiteArgs Empty = new GetInstallationSiteArgs();

    /**
     * The Fleet-unique identifier of the related application.
     * 
     */
    @Import(name="applicationId")
    private @Nullable Output<String> applicationId;

    /**
     * @return The Fleet-unique identifier of the related application.
     * 
     */
    public Optional<Output<String>> applicationId() {
        return Optional.ofNullable(this.applicationId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     * 
     */
    @Import(name="fleetId", required=true)
    private Output<String> fleetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
     * 
     */
    public Output<String> fleetId() {
        return this.fleetId;
    }

    /**
     * The file system path of the installation.
     * 
     */
    @Import(name="installationPath")
    private @Nullable Output<String> installationPath;

    /**
     * @return The file system path of the installation.
     * 
     */
    public Optional<Output<String>> installationPath() {
        return Optional.ofNullable(this.installationPath);
    }

    /**
     * The distribution of the related Java Runtime.
     * 
     */
    @Import(name="jreDistribution")
    private @Nullable Output<String> jreDistribution;

    /**
     * @return The distribution of the related Java Runtime.
     * 
     */
    public Optional<Output<String>> jreDistribution() {
        return Optional.ofNullable(this.jreDistribution);
    }

    /**
     * The security status of the Java Runtime.
     * 
     */
    @Import(name="jreSecurityStatus")
    private @Nullable Output<String> jreSecurityStatus;

    /**
     * @return The security status of the Java Runtime.
     * 
     */
    public Optional<Output<String>> jreSecurityStatus() {
        return Optional.ofNullable(this.jreSecurityStatus);
    }

    /**
     * The vendor of the related Java Runtime.
     * 
     */
    @Import(name="jreVendor")
    private @Nullable Output<String> jreVendor;

    /**
     * @return The vendor of the related Java Runtime.
     * 
     */
    public Optional<Output<String>> jreVendor() {
        return Optional.ofNullable(this.jreVendor);
    }

    /**
     * The version of the related Java Runtime.
     * 
     */
    @Import(name="jreVersion")
    private @Nullable Output<String> jreVersion;

    /**
     * @return The version of the related Java Runtime.
     * 
     */
    public Optional<Output<String>> jreVersion() {
        return Optional.ofNullable(this.jreVersion);
    }

    /**
     * The Fleet-unique identifier of the related managed instance.
     * 
     */
    @Import(name="managedInstanceId")
    private @Nullable Output<String> managedInstanceId;

    /**
     * @return The Fleet-unique identifier of the related managed instance.
     * 
     */
    public Optional<Output<String>> managedInstanceId() {
        return Optional.ofNullable(this.managedInstanceId);
    }

    /**
     * The operating system type.
     * 
     */
    @Import(name="osFamilies")
    private @Nullable Output<List<String>> osFamilies;

    /**
     * @return The operating system type.
     * 
     */
    public Optional<Output<List<String>>> osFamilies() {
        return Optional.ofNullable(this.osFamilies);
    }

    /**
     * Filter the list with path contains the given value.
     * 
     */
    @Import(name="pathContains")
    private @Nullable Output<String> pathContains;

    /**
     * @return Filter the list with path contains the given value.
     * 
     */
    public Optional<Output<String>> pathContains() {
        return Optional.ofNullable(this.pathContains);
    }

    /**
     * The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    @Import(name="timeEnd")
    private @Nullable Output<String> timeEnd;

    /**
     * @return The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public Optional<Output<String>> timeEnd() {
        return Optional.ofNullable(this.timeEnd);
    }

    /**
     * The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    @Import(name="timeStart")
    private @Nullable Output<String> timeStart;

    /**
     * @return The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     * 
     */
    public Optional<Output<String>> timeStart() {
        return Optional.ofNullable(this.timeStart);
    }

    private GetInstallationSiteArgs() {}

    private GetInstallationSiteArgs(GetInstallationSiteArgs $) {
        this.applicationId = $.applicationId;
        this.fleetId = $.fleetId;
        this.installationPath = $.installationPath;
        this.jreDistribution = $.jreDistribution;
        this.jreSecurityStatus = $.jreSecurityStatus;
        this.jreVendor = $.jreVendor;
        this.jreVersion = $.jreVersion;
        this.managedInstanceId = $.managedInstanceId;
        this.osFamilies = $.osFamilies;
        this.pathContains = $.pathContains;
        this.timeEnd = $.timeEnd;
        this.timeStart = $.timeStart;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetInstallationSiteArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetInstallationSiteArgs $;

        public Builder() {
            $ = new GetInstallationSiteArgs();
        }

        public Builder(GetInstallationSiteArgs defaults) {
            $ = new GetInstallationSiteArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param applicationId The Fleet-unique identifier of the related application.
         * 
         * @return builder
         * 
         */
        public Builder applicationId(@Nullable Output<String> applicationId) {
            $.applicationId = applicationId;
            return this;
        }

        /**
         * @param applicationId The Fleet-unique identifier of the related application.
         * 
         * @return builder
         * 
         */
        public Builder applicationId(String applicationId) {
            return applicationId(Output.of(applicationId));
        }

        /**
         * @param fleetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder fleetId(Output<String> fleetId) {
            $.fleetId = fleetId;
            return this;
        }

        /**
         * @param fleetId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
         * 
         * @return builder
         * 
         */
        public Builder fleetId(String fleetId) {
            return fleetId(Output.of(fleetId));
        }

        /**
         * @param installationPath The file system path of the installation.
         * 
         * @return builder
         * 
         */
        public Builder installationPath(@Nullable Output<String> installationPath) {
            $.installationPath = installationPath;
            return this;
        }

        /**
         * @param installationPath The file system path of the installation.
         * 
         * @return builder
         * 
         */
        public Builder installationPath(String installationPath) {
            return installationPath(Output.of(installationPath));
        }

        /**
         * @param jreDistribution The distribution of the related Java Runtime.
         * 
         * @return builder
         * 
         */
        public Builder jreDistribution(@Nullable Output<String> jreDistribution) {
            $.jreDistribution = jreDistribution;
            return this;
        }

        /**
         * @param jreDistribution The distribution of the related Java Runtime.
         * 
         * @return builder
         * 
         */
        public Builder jreDistribution(String jreDistribution) {
            return jreDistribution(Output.of(jreDistribution));
        }

        /**
         * @param jreSecurityStatus The security status of the Java Runtime.
         * 
         * @return builder
         * 
         */
        public Builder jreSecurityStatus(@Nullable Output<String> jreSecurityStatus) {
            $.jreSecurityStatus = jreSecurityStatus;
            return this;
        }

        /**
         * @param jreSecurityStatus The security status of the Java Runtime.
         * 
         * @return builder
         * 
         */
        public Builder jreSecurityStatus(String jreSecurityStatus) {
            return jreSecurityStatus(Output.of(jreSecurityStatus));
        }

        /**
         * @param jreVendor The vendor of the related Java Runtime.
         * 
         * @return builder
         * 
         */
        public Builder jreVendor(@Nullable Output<String> jreVendor) {
            $.jreVendor = jreVendor;
            return this;
        }

        /**
         * @param jreVendor The vendor of the related Java Runtime.
         * 
         * @return builder
         * 
         */
        public Builder jreVendor(String jreVendor) {
            return jreVendor(Output.of(jreVendor));
        }

        /**
         * @param jreVersion The version of the related Java Runtime.
         * 
         * @return builder
         * 
         */
        public Builder jreVersion(@Nullable Output<String> jreVersion) {
            $.jreVersion = jreVersion;
            return this;
        }

        /**
         * @param jreVersion The version of the related Java Runtime.
         * 
         * @return builder
         * 
         */
        public Builder jreVersion(String jreVersion) {
            return jreVersion(Output.of(jreVersion));
        }

        /**
         * @param managedInstanceId The Fleet-unique identifier of the related managed instance.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(@Nullable Output<String> managedInstanceId) {
            $.managedInstanceId = managedInstanceId;
            return this;
        }

        /**
         * @param managedInstanceId The Fleet-unique identifier of the related managed instance.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(String managedInstanceId) {
            return managedInstanceId(Output.of(managedInstanceId));
        }

        /**
         * @param osFamilies The operating system type.
         * 
         * @return builder
         * 
         */
        public Builder osFamilies(@Nullable Output<List<String>> osFamilies) {
            $.osFamilies = osFamilies;
            return this;
        }

        /**
         * @param osFamilies The operating system type.
         * 
         * @return builder
         * 
         */
        public Builder osFamilies(List<String> osFamilies) {
            return osFamilies(Output.of(osFamilies));
        }

        /**
         * @param osFamilies The operating system type.
         * 
         * @return builder
         * 
         */
        public Builder osFamilies(String... osFamilies) {
            return osFamilies(List.of(osFamilies));
        }

        /**
         * @param pathContains Filter the list with path contains the given value.
         * 
         * @return builder
         * 
         */
        public Builder pathContains(@Nullable Output<String> pathContains) {
            $.pathContains = pathContains;
            return this;
        }

        /**
         * @param pathContains Filter the list with path contains the given value.
         * 
         * @return builder
         * 
         */
        public Builder pathContains(String pathContains) {
            return pathContains(Output.of(pathContains));
        }

        /**
         * @param timeEnd The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeEnd(@Nullable Output<String> timeEnd) {
            $.timeEnd = timeEnd;
            return this;
        }

        /**
         * @param timeEnd The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeEnd(String timeEnd) {
            return timeEnd(Output.of(timeEnd));
        }

        /**
         * @param timeStart The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeStart(@Nullable Output<String> timeStart) {
            $.timeStart = timeStart;
            return this;
        }

        /**
         * @param timeStart The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
         * 
         * @return builder
         * 
         */
        public Builder timeStart(String timeStart) {
            return timeStart(Output.of(timeStart));
        }

        public GetInstallationSiteArgs build() {
            if ($.fleetId == null) {
                throw new MissingRequiredPropertyException("GetInstallationSiteArgs", "fleetId");
            }
            return $;
        }
    }

}
