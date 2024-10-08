// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.OsManagement.inputs.ManagedInstanceAutonomouseArgs;
import com.pulumi.oci.OsManagement.inputs.ManagedInstanceChildSoftwareSourceArgs;
import com.pulumi.oci.OsManagement.inputs.ManagedInstanceManagedInstanceGroupArgs;
import com.pulumi.oci.OsManagement.inputs.ManagedInstanceParentSoftwareSourceArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagedInstanceState extends com.pulumi.resources.ResourceArgs {

    public static final ManagedInstanceState Empty = new ManagedInstanceState();

    /**
     * if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
     * 
     */
    @Import(name="autonomouses")
    private @Nullable Output<List<ManagedInstanceAutonomouseArgs>> autonomouses;

    /**
     * @return if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
     * 
     */
    public Optional<Output<List<ManagedInstanceAutonomouseArgs>>> autonomouses() {
        return Optional.ofNullable(this.autonomouses);
    }

    /**
     * Number of bug fix type updates available to be installed
     * 
     */
    @Import(name="bugUpdatesAvailable")
    private @Nullable Output<Integer> bugUpdatesAvailable;

    /**
     * @return Number of bug fix type updates available to be installed
     * 
     */
    public Optional<Output<Integer>> bugUpdatesAvailable() {
        return Optional.ofNullable(this.bugUpdatesAvailable);
    }

    /**
     * list of child Software Sources attached to the Managed Instance
     * 
     */
    @Import(name="childSoftwareSources")
    private @Nullable Output<List<ManagedInstanceChildSoftwareSourceArgs>> childSoftwareSources;

    /**
     * @return list of child Software Sources attached to the Managed Instance
     * 
     */
    public Optional<Output<List<ManagedInstanceChildSoftwareSourceArgs>>> childSoftwareSources() {
        return Optional.ofNullable(this.childSoftwareSources);
    }

    /**
     * OCID for the Compartment
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return OCID for the Compartment
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * Information specified by the user about the managed instance
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return Information specified by the user about the managed instance
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * User friendly name
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return User friendly name
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * Number of enhancement type updates available to be installed
     * 
     */
    @Import(name="enhancementUpdatesAvailable")
    private @Nullable Output<Integer> enhancementUpdatesAvailable;

    /**
     * @return Number of enhancement type updates available to be installed
     * 
     */
    public Optional<Output<Integer>> enhancementUpdatesAvailable() {
        return Optional.ofNullable(this.enhancementUpdatesAvailable);
    }

    /**
     * (Updatable) True if user allow data collection for this instance
     * 
     */
    @Import(name="isDataCollectionAuthorized")
    private @Nullable Output<Boolean> isDataCollectionAuthorized;

    /**
     * @return (Updatable) True if user allow data collection for this instance
     * 
     */
    public Optional<Output<Boolean>> isDataCollectionAuthorized() {
        return Optional.ofNullable(this.isDataCollectionAuthorized);
    }

    /**
     * Indicates whether a reboot is required to complete installation of updates.
     * 
     */
    @Import(name="isRebootRequired")
    private @Nullable Output<Boolean> isRebootRequired;

    /**
     * @return Indicates whether a reboot is required to complete installation of updates.
     * 
     */
    public Optional<Output<Boolean>> isRebootRequired() {
        return Optional.ofNullable(this.isRebootRequired);
    }

    /**
     * The ksplice effective kernel version
     * 
     */
    @Import(name="kspliceEffectiveKernelVersion")
    private @Nullable Output<String> kspliceEffectiveKernelVersion;

    /**
     * @return The ksplice effective kernel version
     * 
     */
    public Optional<Output<String>> kspliceEffectiveKernelVersion() {
        return Optional.ofNullable(this.kspliceEffectiveKernelVersion);
    }

    /**
     * Time at which the instance last booted
     * 
     */
    @Import(name="lastBoot")
    private @Nullable Output<String> lastBoot;

    /**
     * @return Time at which the instance last booted
     * 
     */
    public Optional<Output<String>> lastBoot() {
        return Optional.ofNullable(this.lastBoot);
    }

    /**
     * Time at which the instance last checked in
     * 
     */
    @Import(name="lastCheckin")
    private @Nullable Output<String> lastCheckin;

    /**
     * @return Time at which the instance last checked in
     * 
     */
    public Optional<Output<String>> lastCheckin() {
        return Optional.ofNullable(this.lastCheckin);
    }

    /**
     * The ids of the managed instance groups of which this instance is a member.
     * 
     */
    @Import(name="managedInstanceGroups")
    private @Nullable Output<List<ManagedInstanceManagedInstanceGroupArgs>> managedInstanceGroups;

    /**
     * @return The ids of the managed instance groups of which this instance is a member.
     * 
     */
    public Optional<Output<List<ManagedInstanceManagedInstanceGroupArgs>>> managedInstanceGroups() {
        return Optional.ofNullable(this.managedInstanceGroups);
    }

    /**
     * OCID for the managed instance
     * 
     */
    @Import(name="managedInstanceId")
    private @Nullable Output<String> managedInstanceId;

    /**
     * @return OCID for the managed instance
     * 
     */
    public Optional<Output<String>> managedInstanceId() {
        return Optional.ofNullable(this.managedInstanceId);
    }

    /**
     * (Updatable) OCID of the ONS topic used to send notification to users
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="notificationTopicId")
    private @Nullable Output<String> notificationTopicId;

    /**
     * @return (Updatable) OCID of the ONS topic used to send notification to users
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> notificationTopicId() {
        return Optional.ofNullable(this.notificationTopicId);
    }

    /**
     * The Operating System type of the managed instance.
     * 
     */
    @Import(name="osFamily")
    private @Nullable Output<String> osFamily;

    /**
     * @return The Operating System type of the managed instance.
     * 
     */
    public Optional<Output<String>> osFamily() {
        return Optional.ofNullable(this.osFamily);
    }

    /**
     * Operating System Kernel Version
     * 
     */
    @Import(name="osKernelVersion")
    private @Nullable Output<String> osKernelVersion;

    /**
     * @return Operating System Kernel Version
     * 
     */
    public Optional<Output<String>> osKernelVersion() {
        return Optional.ofNullable(this.osKernelVersion);
    }

    /**
     * Operating System Name
     * 
     */
    @Import(name="osName")
    private @Nullable Output<String> osName;

    /**
     * @return Operating System Name
     * 
     */
    public Optional<Output<String>> osName() {
        return Optional.ofNullable(this.osName);
    }

    /**
     * Operating System Version
     * 
     */
    @Import(name="osVersion")
    private @Nullable Output<String> osVersion;

    /**
     * @return Operating System Version
     * 
     */
    public Optional<Output<String>> osVersion() {
        return Optional.ofNullable(this.osVersion);
    }

    /**
     * Number of non-classified updates available to be installed
     * 
     */
    @Import(name="otherUpdatesAvailable")
    private @Nullable Output<Integer> otherUpdatesAvailable;

    /**
     * @return Number of non-classified updates available to be installed
     * 
     */
    public Optional<Output<Integer>> otherUpdatesAvailable() {
        return Optional.ofNullable(this.otherUpdatesAvailable);
    }

    /**
     * the parent (base) Software Source attached to the Managed Instance
     * 
     */
    @Import(name="parentSoftwareSources")
    private @Nullable Output<List<ManagedInstanceParentSoftwareSourceArgs>> parentSoftwareSources;

    /**
     * @return the parent (base) Software Source attached to the Managed Instance
     * 
     */
    public Optional<Output<List<ManagedInstanceParentSoftwareSourceArgs>>> parentSoftwareSources() {
        return Optional.ofNullable(this.parentSoftwareSources);
    }

    /**
     * Number of scheduled jobs associated with this instance
     * 
     */
    @Import(name="scheduledJobCount")
    private @Nullable Output<Integer> scheduledJobCount;

    /**
     * @return Number of scheduled jobs associated with this instance
     * 
     */
    public Optional<Output<Integer>> scheduledJobCount() {
        return Optional.ofNullable(this.scheduledJobCount);
    }

    /**
     * Number of security type updates available to be installed
     * 
     */
    @Import(name="securityUpdatesAvailable")
    private @Nullable Output<Integer> securityUpdatesAvailable;

    /**
     * @return Number of security type updates available to be installed
     * 
     */
    public Optional<Output<Integer>> securityUpdatesAvailable() {
        return Optional.ofNullable(this.securityUpdatesAvailable);
    }

    /**
     * status of the managed instance.
     * 
     */
    @Import(name="status")
    private @Nullable Output<String> status;

    /**
     * @return status of the managed instance.
     * 
     */
    public Optional<Output<String>> status() {
        return Optional.ofNullable(this.status);
    }

    /**
     * Number of updates available to be installed
     * 
     */
    @Import(name="updatesAvailable")
    private @Nullable Output<Integer> updatesAvailable;

    /**
     * @return Number of updates available to be installed
     * 
     */
    public Optional<Output<Integer>> updatesAvailable() {
        return Optional.ofNullable(this.updatesAvailable);
    }

    /**
     * Number of work requests associated with this instance
     * 
     */
    @Import(name="workRequestCount")
    private @Nullable Output<Integer> workRequestCount;

    /**
     * @return Number of work requests associated with this instance
     * 
     */
    public Optional<Output<Integer>> workRequestCount() {
        return Optional.ofNullable(this.workRequestCount);
    }

    private ManagedInstanceState() {}

    private ManagedInstanceState(ManagedInstanceState $) {
        this.autonomouses = $.autonomouses;
        this.bugUpdatesAvailable = $.bugUpdatesAvailable;
        this.childSoftwareSources = $.childSoftwareSources;
        this.compartmentId = $.compartmentId;
        this.description = $.description;
        this.displayName = $.displayName;
        this.enhancementUpdatesAvailable = $.enhancementUpdatesAvailable;
        this.isDataCollectionAuthorized = $.isDataCollectionAuthorized;
        this.isRebootRequired = $.isRebootRequired;
        this.kspliceEffectiveKernelVersion = $.kspliceEffectiveKernelVersion;
        this.lastBoot = $.lastBoot;
        this.lastCheckin = $.lastCheckin;
        this.managedInstanceGroups = $.managedInstanceGroups;
        this.managedInstanceId = $.managedInstanceId;
        this.notificationTopicId = $.notificationTopicId;
        this.osFamily = $.osFamily;
        this.osKernelVersion = $.osKernelVersion;
        this.osName = $.osName;
        this.osVersion = $.osVersion;
        this.otherUpdatesAvailable = $.otherUpdatesAvailable;
        this.parentSoftwareSources = $.parentSoftwareSources;
        this.scheduledJobCount = $.scheduledJobCount;
        this.securityUpdatesAvailable = $.securityUpdatesAvailable;
        this.status = $.status;
        this.updatesAvailable = $.updatesAvailable;
        this.workRequestCount = $.workRequestCount;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagedInstanceState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagedInstanceState $;

        public Builder() {
            $ = new ManagedInstanceState();
        }

        public Builder(ManagedInstanceState defaults) {
            $ = new ManagedInstanceState(Objects.requireNonNull(defaults));
        }

        /**
         * @param autonomouses if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
         * 
         * @return builder
         * 
         */
        public Builder autonomouses(@Nullable Output<List<ManagedInstanceAutonomouseArgs>> autonomouses) {
            $.autonomouses = autonomouses;
            return this;
        }

        /**
         * @param autonomouses if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
         * 
         * @return builder
         * 
         */
        public Builder autonomouses(List<ManagedInstanceAutonomouseArgs> autonomouses) {
            return autonomouses(Output.of(autonomouses));
        }

        /**
         * @param autonomouses if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
         * 
         * @return builder
         * 
         */
        public Builder autonomouses(ManagedInstanceAutonomouseArgs... autonomouses) {
            return autonomouses(List.of(autonomouses));
        }

        /**
         * @param bugUpdatesAvailable Number of bug fix type updates available to be installed
         * 
         * @return builder
         * 
         */
        public Builder bugUpdatesAvailable(@Nullable Output<Integer> bugUpdatesAvailable) {
            $.bugUpdatesAvailable = bugUpdatesAvailable;
            return this;
        }

        /**
         * @param bugUpdatesAvailable Number of bug fix type updates available to be installed
         * 
         * @return builder
         * 
         */
        public Builder bugUpdatesAvailable(Integer bugUpdatesAvailable) {
            return bugUpdatesAvailable(Output.of(bugUpdatesAvailable));
        }

        /**
         * @param childSoftwareSources list of child Software Sources attached to the Managed Instance
         * 
         * @return builder
         * 
         */
        public Builder childSoftwareSources(@Nullable Output<List<ManagedInstanceChildSoftwareSourceArgs>> childSoftwareSources) {
            $.childSoftwareSources = childSoftwareSources;
            return this;
        }

        /**
         * @param childSoftwareSources list of child Software Sources attached to the Managed Instance
         * 
         * @return builder
         * 
         */
        public Builder childSoftwareSources(List<ManagedInstanceChildSoftwareSourceArgs> childSoftwareSources) {
            return childSoftwareSources(Output.of(childSoftwareSources));
        }

        /**
         * @param childSoftwareSources list of child Software Sources attached to the Managed Instance
         * 
         * @return builder
         * 
         */
        public Builder childSoftwareSources(ManagedInstanceChildSoftwareSourceArgs... childSoftwareSources) {
            return childSoftwareSources(List.of(childSoftwareSources));
        }

        /**
         * @param compartmentId OCID for the Compartment
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId OCID for the Compartment
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param description Information specified by the user about the managed instance
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description Information specified by the user about the managed instance
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName User friendly name
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName User friendly name
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param enhancementUpdatesAvailable Number of enhancement type updates available to be installed
         * 
         * @return builder
         * 
         */
        public Builder enhancementUpdatesAvailable(@Nullable Output<Integer> enhancementUpdatesAvailable) {
            $.enhancementUpdatesAvailable = enhancementUpdatesAvailable;
            return this;
        }

        /**
         * @param enhancementUpdatesAvailable Number of enhancement type updates available to be installed
         * 
         * @return builder
         * 
         */
        public Builder enhancementUpdatesAvailable(Integer enhancementUpdatesAvailable) {
            return enhancementUpdatesAvailable(Output.of(enhancementUpdatesAvailable));
        }

        /**
         * @param isDataCollectionAuthorized (Updatable) True if user allow data collection for this instance
         * 
         * @return builder
         * 
         */
        public Builder isDataCollectionAuthorized(@Nullable Output<Boolean> isDataCollectionAuthorized) {
            $.isDataCollectionAuthorized = isDataCollectionAuthorized;
            return this;
        }

        /**
         * @param isDataCollectionAuthorized (Updatable) True if user allow data collection for this instance
         * 
         * @return builder
         * 
         */
        public Builder isDataCollectionAuthorized(Boolean isDataCollectionAuthorized) {
            return isDataCollectionAuthorized(Output.of(isDataCollectionAuthorized));
        }

        /**
         * @param isRebootRequired Indicates whether a reboot is required to complete installation of updates.
         * 
         * @return builder
         * 
         */
        public Builder isRebootRequired(@Nullable Output<Boolean> isRebootRequired) {
            $.isRebootRequired = isRebootRequired;
            return this;
        }

        /**
         * @param isRebootRequired Indicates whether a reboot is required to complete installation of updates.
         * 
         * @return builder
         * 
         */
        public Builder isRebootRequired(Boolean isRebootRequired) {
            return isRebootRequired(Output.of(isRebootRequired));
        }

        /**
         * @param kspliceEffectiveKernelVersion The ksplice effective kernel version
         * 
         * @return builder
         * 
         */
        public Builder kspliceEffectiveKernelVersion(@Nullable Output<String> kspliceEffectiveKernelVersion) {
            $.kspliceEffectiveKernelVersion = kspliceEffectiveKernelVersion;
            return this;
        }

        /**
         * @param kspliceEffectiveKernelVersion The ksplice effective kernel version
         * 
         * @return builder
         * 
         */
        public Builder kspliceEffectiveKernelVersion(String kspliceEffectiveKernelVersion) {
            return kspliceEffectiveKernelVersion(Output.of(kspliceEffectiveKernelVersion));
        }

        /**
         * @param lastBoot Time at which the instance last booted
         * 
         * @return builder
         * 
         */
        public Builder lastBoot(@Nullable Output<String> lastBoot) {
            $.lastBoot = lastBoot;
            return this;
        }

        /**
         * @param lastBoot Time at which the instance last booted
         * 
         * @return builder
         * 
         */
        public Builder lastBoot(String lastBoot) {
            return lastBoot(Output.of(lastBoot));
        }

        /**
         * @param lastCheckin Time at which the instance last checked in
         * 
         * @return builder
         * 
         */
        public Builder lastCheckin(@Nullable Output<String> lastCheckin) {
            $.lastCheckin = lastCheckin;
            return this;
        }

        /**
         * @param lastCheckin Time at which the instance last checked in
         * 
         * @return builder
         * 
         */
        public Builder lastCheckin(String lastCheckin) {
            return lastCheckin(Output.of(lastCheckin));
        }

        /**
         * @param managedInstanceGroups The ids of the managed instance groups of which this instance is a member.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceGroups(@Nullable Output<List<ManagedInstanceManagedInstanceGroupArgs>> managedInstanceGroups) {
            $.managedInstanceGroups = managedInstanceGroups;
            return this;
        }

        /**
         * @param managedInstanceGroups The ids of the managed instance groups of which this instance is a member.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceGroups(List<ManagedInstanceManagedInstanceGroupArgs> managedInstanceGroups) {
            return managedInstanceGroups(Output.of(managedInstanceGroups));
        }

        /**
         * @param managedInstanceGroups The ids of the managed instance groups of which this instance is a member.
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceGroups(ManagedInstanceManagedInstanceGroupArgs... managedInstanceGroups) {
            return managedInstanceGroups(List.of(managedInstanceGroups));
        }

        /**
         * @param managedInstanceId OCID for the managed instance
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(@Nullable Output<String> managedInstanceId) {
            $.managedInstanceId = managedInstanceId;
            return this;
        }

        /**
         * @param managedInstanceId OCID for the managed instance
         * 
         * @return builder
         * 
         */
        public Builder managedInstanceId(String managedInstanceId) {
            return managedInstanceId(Output.of(managedInstanceId));
        }

        /**
         * @param notificationTopicId (Updatable) OCID of the ONS topic used to send notification to users
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder notificationTopicId(@Nullable Output<String> notificationTopicId) {
            $.notificationTopicId = notificationTopicId;
            return this;
        }

        /**
         * @param notificationTopicId (Updatable) OCID of the ONS topic used to send notification to users
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder notificationTopicId(String notificationTopicId) {
            return notificationTopicId(Output.of(notificationTopicId));
        }

        /**
         * @param osFamily The Operating System type of the managed instance.
         * 
         * @return builder
         * 
         */
        public Builder osFamily(@Nullable Output<String> osFamily) {
            $.osFamily = osFamily;
            return this;
        }

        /**
         * @param osFamily The Operating System type of the managed instance.
         * 
         * @return builder
         * 
         */
        public Builder osFamily(String osFamily) {
            return osFamily(Output.of(osFamily));
        }

        /**
         * @param osKernelVersion Operating System Kernel Version
         * 
         * @return builder
         * 
         */
        public Builder osKernelVersion(@Nullable Output<String> osKernelVersion) {
            $.osKernelVersion = osKernelVersion;
            return this;
        }

        /**
         * @param osKernelVersion Operating System Kernel Version
         * 
         * @return builder
         * 
         */
        public Builder osKernelVersion(String osKernelVersion) {
            return osKernelVersion(Output.of(osKernelVersion));
        }

        /**
         * @param osName Operating System Name
         * 
         * @return builder
         * 
         */
        public Builder osName(@Nullable Output<String> osName) {
            $.osName = osName;
            return this;
        }

        /**
         * @param osName Operating System Name
         * 
         * @return builder
         * 
         */
        public Builder osName(String osName) {
            return osName(Output.of(osName));
        }

        /**
         * @param osVersion Operating System Version
         * 
         * @return builder
         * 
         */
        public Builder osVersion(@Nullable Output<String> osVersion) {
            $.osVersion = osVersion;
            return this;
        }

        /**
         * @param osVersion Operating System Version
         * 
         * @return builder
         * 
         */
        public Builder osVersion(String osVersion) {
            return osVersion(Output.of(osVersion));
        }

        /**
         * @param otherUpdatesAvailable Number of non-classified updates available to be installed
         * 
         * @return builder
         * 
         */
        public Builder otherUpdatesAvailable(@Nullable Output<Integer> otherUpdatesAvailable) {
            $.otherUpdatesAvailable = otherUpdatesAvailable;
            return this;
        }

        /**
         * @param otherUpdatesAvailable Number of non-classified updates available to be installed
         * 
         * @return builder
         * 
         */
        public Builder otherUpdatesAvailable(Integer otherUpdatesAvailable) {
            return otherUpdatesAvailable(Output.of(otherUpdatesAvailable));
        }

        /**
         * @param parentSoftwareSources the parent (base) Software Source attached to the Managed Instance
         * 
         * @return builder
         * 
         */
        public Builder parentSoftwareSources(@Nullable Output<List<ManagedInstanceParentSoftwareSourceArgs>> parentSoftwareSources) {
            $.parentSoftwareSources = parentSoftwareSources;
            return this;
        }

        /**
         * @param parentSoftwareSources the parent (base) Software Source attached to the Managed Instance
         * 
         * @return builder
         * 
         */
        public Builder parentSoftwareSources(List<ManagedInstanceParentSoftwareSourceArgs> parentSoftwareSources) {
            return parentSoftwareSources(Output.of(parentSoftwareSources));
        }

        /**
         * @param parentSoftwareSources the parent (base) Software Source attached to the Managed Instance
         * 
         * @return builder
         * 
         */
        public Builder parentSoftwareSources(ManagedInstanceParentSoftwareSourceArgs... parentSoftwareSources) {
            return parentSoftwareSources(List.of(parentSoftwareSources));
        }

        /**
         * @param scheduledJobCount Number of scheduled jobs associated with this instance
         * 
         * @return builder
         * 
         */
        public Builder scheduledJobCount(@Nullable Output<Integer> scheduledJobCount) {
            $.scheduledJobCount = scheduledJobCount;
            return this;
        }

        /**
         * @param scheduledJobCount Number of scheduled jobs associated with this instance
         * 
         * @return builder
         * 
         */
        public Builder scheduledJobCount(Integer scheduledJobCount) {
            return scheduledJobCount(Output.of(scheduledJobCount));
        }

        /**
         * @param securityUpdatesAvailable Number of security type updates available to be installed
         * 
         * @return builder
         * 
         */
        public Builder securityUpdatesAvailable(@Nullable Output<Integer> securityUpdatesAvailable) {
            $.securityUpdatesAvailable = securityUpdatesAvailable;
            return this;
        }

        /**
         * @param securityUpdatesAvailable Number of security type updates available to be installed
         * 
         * @return builder
         * 
         */
        public Builder securityUpdatesAvailable(Integer securityUpdatesAvailable) {
            return securityUpdatesAvailable(Output.of(securityUpdatesAvailable));
        }

        /**
         * @param status status of the managed instance.
         * 
         * @return builder
         * 
         */
        public Builder status(@Nullable Output<String> status) {
            $.status = status;
            return this;
        }

        /**
         * @param status status of the managed instance.
         * 
         * @return builder
         * 
         */
        public Builder status(String status) {
            return status(Output.of(status));
        }

        /**
         * @param updatesAvailable Number of updates available to be installed
         * 
         * @return builder
         * 
         */
        public Builder updatesAvailable(@Nullable Output<Integer> updatesAvailable) {
            $.updatesAvailable = updatesAvailable;
            return this;
        }

        /**
         * @param updatesAvailable Number of updates available to be installed
         * 
         * @return builder
         * 
         */
        public Builder updatesAvailable(Integer updatesAvailable) {
            return updatesAvailable(Output.of(updatesAvailable));
        }

        /**
         * @param workRequestCount Number of work requests associated with this instance
         * 
         * @return builder
         * 
         */
        public Builder workRequestCount(@Nullable Output<Integer> workRequestCount) {
            $.workRequestCount = workRequestCount;
            return this;
        }

        /**
         * @param workRequestCount Number of work requests associated with this instance
         * 
         * @return builder
         * 
         */
        public Builder workRequestCount(Integer workRequestCount) {
            return workRequestCount(Output.of(workRequestCount));
        }

        public ManagedInstanceState build() {
            return $;
        }
    }

}
