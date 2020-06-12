//
//  NetworkController.swift
//  SDHome
//


import UIKit

class NetworkViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        print("Network Monitoring page loaded")
    }
    
    @IBAction func NetworkReturnBtn(_ sender: Any) {
        self.performSegue(withIdentifier: "NetworkReturn", sender:self)
    }
    

}
