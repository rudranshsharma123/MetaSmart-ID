# MetaSmart ID

## Description

This project aims to create an interoperable identity platform for the metaverse, ensuring that the identities are W3C compliant. The primary goals include issuing verifiable credentials (VCs) and storing the data in one Hyperledger Fabric network, which can then interoperate with another Fabric network to share the stored data. The project also focuses on minimal data sharing during the verification process.

## Specifications

1. **Goal**: The project aims to establish an interoperable identity platform for the metaverse, adhering to W3C compliance standards for identities.
2. **VC Issuance**: The system allows for the issuing of verifiable credentials (VCs) within the metaverse.
3. **Data Storage**: The project employs one Hyperledger Fabric network to store the data and facilitates interoperability with another Fabric network to share the stored information.
4. **Minimal Data Sharing**: The system ensures that during the verification process, only essential data is shared to maintain privacy.

## Solution Specifications

To achieve the goals outlined above, the project utilizes the following technologies:

1. **Hyperledger Indy**: The solution employs Indy's SDK, Node, and Plenum components to handle all aspects of credentials, from issuance to verification.
2. **Hyperledger Cacti**: Hyperledger Cacti is utilized for interoperation between two Hyperledger Fabric networks, enabling seamless communication and data sharing.
3. **Hyperledger Fabric**: Two Hyperledger Fabric networks are employed to facilitate interoperability and enable the storage and sharing of data.

## Technology Stack

The project employs the following technologies to achieve its objectives:

1. **Hyperledger Indy**: Hyperledger Indy is a powerful distributed ledger technology (DLT) specifically designed for decentralized identity management. It provides a robust and secure platform for managing digital identities within the metaverse. With its SDK, Node, and Plenum components, Hyperledger Indy enables the project to handle various aspects of credentials, including issuance and verification. This technology ensures the highest level of privacy, security, and interoperability for identity management in the metaverse.

2. **Hyperledger Cacti**: Hyperledger Cacti serves as an essential interoperability framework in this project. It enables seamless communication and data sharing between different blockchain networks. By leveraging Hyperledger Cacti, the project can establish interoperation between two Hyperledger Fabric networks. This facilitates the smooth transfer and synchronization of data between the networks, enhancing the overall interoperability and functionality of the identity platform in the metaverse.

3. **Hyperledger Fabric**: Hyperledger Fabric, a permissioned blockchain framework, is a key component of the technology stack. It provides the foundation for building decentralized applications in the project. Hyperledger Fabric offers features such as high throughput, scalability, and privacy, making it an ideal choice for enterprise-grade solutions. In this project, two interconnected Hyperledger Fabric networks are utilized. One network serves as the primary data storage solution, while the other network enables interoperability and data sharing. Hyperledger Fabric ensures the secure and efficient storage, retrieval, and transfer of verifiable credentials in the metaverse.

4. **Flask**: Flask, a popular Python web framework, powers the server-side application. It provides a flexible and lightweight environment for running the backend of the project. Flask handles the communication between the client and the backend systems, processing requests and generating appropriate responses. With its simplicity and extensibility, Flask enables smooth integration with other components of the technology stack, creating a reliable and scalable server infrastructure for the metaverse identity platform.

5. **Socket.IO**: Socket.IO, a JavaScript library, plays a crucial role in establishing real-time, bidirectional communication between the server and the client. It enables seamless, event-based communication, allowing instant updates and notifications within the client application. Socket.IO ensures a responsive and interactive user experience, facilitating smooth interactions between users and the metaverse identity platform.

6. **HTML and JavaScript**: The client-side components of the project are developed using standard HTML and JavaScript. HTML provides the structural elements and layout of the user interface, while JavaScript brings interactivity and dynamic behavior to the client-side application. With HTML and JavaScript, the project achieves a user-friendly and intuitive interface, allowing users to interact with the metaverse identity platform seamlessly.

7. **Indy SDK**: Indy SDK is a software development kit provided by Hyperledger Indy. It offers a comprehensive set of tools and libraries for developers to interact with the Indy network. Indy SDK enables the project to connect to the Indy pool running on the local machine, facilitating seamless integration and communication with the decentralized identity infrastructure. With Indy SDK, the project can manage wallets, perform credential operations, and conduct verifications, ensuring the smooth operation and reliable functionality of the metaverse identity platform.

By leveraging this diverse and robust technology stack, the project creates a powerful and interoperable identity platform for the metaverse. These technologies work in harmony to ensure W3C compliance, secure issuance and verification of credentials, and seamless data sharing between interconnected blockchain networks. The combination of privacy, security, and functionality provided by the technology stack forms the foundation for a trusted and reliable identity solution in the metaverse.
## How It Works

1. The project utilizes a Flask server to establish a connection with the client using Socket. IO. This real-time communication protocol enables bidirectional communication between the server and the client, allowing for instant updates and notifications within the client application. The Flask server acts as the central hub for handling requests and responses, facilitating seamless interaction between the client and the backend systems.

2. The client-side application is built using vanilla HTML and JavaScript, providing a user-friendly interface for users to interact with the metaverse identity platform. HTML structures the content and layout of the user interface, while JavaScript adds interactivity and dynamic behavior. This combination ensures a seamless and intuitive user experience, allowing users to navigate through the various functionalities of the platform effortlessly.

3. Upon establishing the connection, the Flask server connects to the Hyperledger Indy pool running on the local machine. The pool consists of nodes that form a decentralized network, enabling secure and private identity management. The connection is established using Genesis transactions, which contain the initial configuration and state of the Indy network. This connection establishes a bridge between the metaverse identity platform and the underlying decentralized identity infrastructure.

4. Once the connection is established, the client initializes the pools and creates wallets for entities such as the government and VeriSmart. These wallets serve as digital containers for storing and managing cryptographic keys and credentials. By creating wallets, the platform ensures secure and isolated storage of sensitive information related to different entities involved in the metaverse ecosystem.

5. The client presents a login screen to users, allowing them to log in using their existing wallets. Upon successful login, the active wallet is set in the backend, ensuring that subsequent operations are performed within the context of the authenticated user. This login mechanism provides personalized access and allows different users to interact with the platform based on their roles and permissions.

6. After successful login, if the user is an admin (currently hardcoded as VeriSmart for the MVP), they gain access to the dashboard. The dashboard serves as the control center for managing credentials and performing various operations. It provides a comprehensive user interface where admins can create schemas for credentials, define credential definitions, issue verifiable credentials, and verify the authenticity of received credentials.

7. Additionally, the dashboard includes an option to store data to the Hyperledger Fabric ledger. This feature enables the persistence of credentials on the blockchain, ensuring immutability and transparency. The platform provides fine-grained consent mechanisms where users can specify their preferences regarding data storage. If consent is not given, only the encoded value of the credential is stored, preserving user privacy while still ensuring the integrity and authenticity of the data.

By following this workflow, the metaverse identity platform seamlessly integrates the server-side Flask application, client-side HTML and JavaScript components, Hyperledger Indy's decentralized identity infrastructure, and Hyperledger Fabric's secure and transparent ledger. This comprehensive approach ensures a robust, privacy-focused, and interoperable identity solution for the metaverse, empowering users with control over their digital identities while facilitating seamless data sharing and verification processes.

## How to Run It

To run the metaverse identity platform, follow these steps:

1. Clone this repository to your local machine using the following command:

   ```
   git clone [<repository-url>](https://github.com/rudranshsharma123/MetaSmart-ID/)
   ```

2. Clone the Hyperledger Indy-SDK repository by navigating to the desired location and executing the following command:

   ```
   git clone https://github.com/hyperledger/indy-sdk/
   ```

   After cloning, refer to the documentation available in the Indy-SDK repository to build it from the source. Follow the provided instructions to ensure a successful build. https://github.com/hyperledger/indy-sdk/blob/main/docs/build-guides/mac-build.md

3. Once the Indy-SDK is built, ensure that the built `libindy` file is in the correct location for it to be pulled into the code. Verify the path and configuration to make sure it is properly integrated with the metaverse identity platform.

4. Navigate to the `docker` folder in the project repository and follow the instructions provided in the README file. This will guide you in building your own pool using the Docker configuration.

5. Utilize the `.txn` file located in the `indy` folder. This file contains the necessary transaction data for the Indy network. Make sure to use it while setting up the pool in the previous step.

6. Run the Flask server by executing the following command in the project root directory:

   ```
   python3 app.py
   ```

7. Open the `index.html` file in your preferred web browser. To serve the HTML file, you can use any server of your choice, such as the Live Server extension in Visual Studio Code.

8. Once the webpage is loaded, click on the "Start Process" button to initiate the metaverse identity platform.

9. For a comprehensive understanding of the platform's functionality while running, refer to the provided video tutorial [here](https://youtu.be/V9SH4d8fVSk). The video will guide you through the various steps and interactions within the metaverse identity platform, showcasing its working principles and features.
10. For interoperation, you would need to install Cacti and build it on your local machine, once it's done follow the steps below
## Interoperation

To enable interoperation with the existing components and network setup, follow these steps:

1. Clone your repository containing all the necessary components to your local machine. Make sure you have the latest version of the repository.

2. Locate the `test-network/fabric` folder within your cloned repository. This folder contains the pre-configured network setup for Hyperledger Fabric.

3. Replace the file with JSON in the `app.py` file with the appropriate location on your machine. The JSON file should be named `chaincode.json` and contains the necessary information for interoperation. This update is essential as it accommodates new users and ensures compatibility with the interoperation functionality provided by Cacti.

By following these steps, you can seamlessly integrate the pre-built components and network setup into the Metaverse identity platform. This interoperation capability allows for smooth data sharing and communication between different blockchain networks, enhancing the functionality and flexibility of the platform.
