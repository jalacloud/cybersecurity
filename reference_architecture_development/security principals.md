# Security Principals

## 1. Defence In Depth

### Description
Defence in Depth is a layered approach to security, designed to provide multiple barriers against threats. By employing a series of defensive mechanisms, if one layer fails, subsequent layers continue to protect the organisation's assets. This strategy involves a combination of technical, administrative, and physical controls across the network, application, and data layers.

### Implications
- **Enhanced Resilience**: The organisation is protected against a broader range of attacks due to the diversity of control types and layers.
- **Complex Attack Surface**: An attacker must overcome multiple security measures, increasing the time and resources required to breach the system.
- **Operational Overhead**: Requires careful planning and coordination of various controls, leading to increased complexity in management and maintenance.

---

## 2. Choke Point

### Description
A choke point is a strategic network location where traffic can be monitored, controlled, and filtered. It is a critical control point that enables the enforcement of security policies, detection of anomalies, and prevention of unauthorised access.

Attackers are forced to use a narrow channel of access which is monitored and controlled, as mentioned above.

### Implications
- **Improved Monitoring**: Centralises traffic analysis, making it easier to detect suspicious activities and enforce security policies.
- **Efficient Access Control**: Simplifies the management of access controls by consolidating them in a single location.
- **Potential Bottlenecks**: Can become a performance or security bottleneck if not properly sized or maintained, potentially affecting network availability.

---

## 3. Weakest Link

### Description
The weakest link principle asserts that the security of a system is only as strong as its most vulnerable component. Attackers often seek out and exploit the weakest aspect of a security system, whether it is a technology, process, or user behaviour.

### Implications
- **Comprehensive Risk Assessment**: Requires regular assessments of all components to identify and strengthen weak points.
- **User Awareness**: Highlights the need for continuous user education and awareness training to minimise human-related vulnerabilities.
- **Resource Allocation**: May necessitate focused investment in bolstering weaker areas to avoid compromising the entire system.

---

## 4. Fail-Safe Stance

### Description
The fail-safe stance principle ensures that, in the event of a failure, systems default to a secure state. This minimises the risk of accidental or intentional security breaches during unexpected disruptions or failures.

### Implications
- **Minimised Exposure**: Systems remain secure even when experiencing failures, reducing the risk of unauthorised access.
- **Operational Disruptions**: May lead to service disruptions if fail-safe mechanisms trigger conservative security measures, impacting user experience.
- **Testing Requirements**: Regular testing of fail-safe mechanisms is essential to ensure they function as intended in real-world scenarios.

---

## 5. Diversity of Defence

### Description
Diversity of Defence involves using different technologies, strategies, and controls to protect against threats. This approach prevents attackers from exploiting a single point of failure by leveraging varied security measures that complement each other.

### Implications
- **Reduced Risk of Common Vulnerabilities**: Using diverse solutions mitigates the risk of a single exploit compromising multiple systems.
- **Increased Complexity**: Can lead to higher complexity in management and integration of disparate systems and controls.
- **Resource Demands**: May require more resources (time, money, people) for implementation and maintenance, including staff training on diverse technologies.

---

## 6. Simplicity of Design

### Description
Simplicity of Design advocates for reducing unnecessary complexity in security architectures. Simple, well-understood designs are easier to manage, audit, and secure, reducing the risk of misconfigurations and vulnerabilities.

### Implications
- **Reduced Error Rate**: Simpler systems are less prone to misconfigurations, making them more reliable and secure.
- **Easier Maintenance**: Simplifies system updates, patching, and audits, reducing the operational overhead.
- **Potential Limitations**: Over-simplification may lead to gaps in security controls if critical functionalities are overlooked or omitted.

---

## 7. Compartmentalisation

### Description
Compartmentalisation involves dividing systems and networks into isolated segments to limit the spread of threats and reduce the impact of a security breach. This principle is often implemented through network segmentation, access controls, and data classification.

### Implications
- **Containment of Breaches**: Limits the movement of attackers within the network, reducing the scope of potential damage.
- **Granular Access Control**: Enhances security by restricting user access to only necessary segments.
- **Increased Configuration Overhead**: Requires careful planning and management of segmentation and access controls, leading to increased administrative complexity.

---

## 8. Protection against Insider and Outsider Threats

### Description
This principle recognises that threats can originate from both within and outside the organisation. It calls for comprehensive security measures that address both malicious insiders and external attackers through monitoring, access controls, and behavioural analysis.

### Implications
- **Holistic Security Approach**: Ensures that security measures protect against a broad spectrum of threats, including those from trusted individuals.
- **Resource Intensive**: Implementing and maintaining measures to monitor and control both internal and external activities can be resource-intensive.
- **Privacy Concerns**: Requires careful consideration of privacy and ethical implications, especially regarding employee monitoring.

---

## 9. Least Privilege

### Description
The least privilege principle states that users and systems should be granted the minimum level of access necessary to perform their functions. This reduces the risk of unauthorised access and limits the potential impact of a security breach.

### Implications
- **Reduced Attack Surface**: Limits the number of opportunities for exploitation by restricting access rights.
- **Operational Challenges**: Can be challenging to implement in dynamic environments where roles and responsibilities frequently change.
- **Increased Management Overhead**: Requires continuous review and adjustment of access controls to ensure alignment with current roles.

---

## 10. Universal Participation

### Description
Universal Participation ensures that all members of an organisation are engaged in maintaining security. It promotes a culture where security is everyone’s responsibility, not just the domain of IT or security teams.

### Implications
- **Improved Security Culture**: Encourages proactive security behaviours and vigilance across all levels of the organisation.
- **Training and Awareness**: Requires ongoing investment in training and awareness programmes to maintain participation.
- **Potential Resistance**: May encounter resistance from employees if security responsibilities are perceived as additional burdens.

---

## 11. Reduced Sign On

### Description
Reduced Sign On refers to the strategy of minimising the number of authentication events required for users to access systems and services. This is often implemented through Single Sign-On (SSO) solutions that balance security and user convenience.

### Implications
- **Enhanced User Experience**: Simplifies user access, reducing the number of credentials that need to be managed and remembered.
- **Security Risks**: A compromise of SSO credentials can lead to unauthorised access to multiple systems, making it a critical security target.
- **Integration Challenges**: Requires careful integration across diverse systems to ensure consistent access management and security.

---

## 12. External Monitoring

### Description
External Monitoring involves observing and analysing activities and threats that originate outside the organisation's network. It includes monitoring threat intelligence sources, third-party services, and the wider internet for potential risks.

The mechanism(s) used to monitor and audit security events is external to the system being monitored to prevent the monitoring mechanism being manipulated to hide an attack.

### Implications
- **Proactive Threat Detection**: Enables the identification of external threats before they impact the organisation.
- **Enhanced Situational Awareness**: Provides a broader understanding of the threat landscape, informing better security decisions.
- **Data Privacy Considerations**: Care must be taken to ensure that external monitoring does not inadvertently infringe on the privacy rights of external entities.

---

## 13. Management Traffic Containment

### Description
Management Traffic Containment focuses on securing and isolating management communications within a network. It ensures that administrative traffic is separated from regular user and application traffic to prevent unauthorised access and manipulation.

### Implications
- **Increased Security for Critical Functions**: Protects sensitive management activities from being intercepted or altered.
- **Complex Network Configurations**: Requires careful design and configuration of network segments and access controls.
- **Operational Constraints**: May introduce additional steps for administrators, potentially impacting the efficiency of management tasks.
